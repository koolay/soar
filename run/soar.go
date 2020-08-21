package run

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/XiaoMi/soar/advisor"
	"github.com/XiaoMi/soar/ast"
	"github.com/XiaoMi/soar/common"
	"github.com/XiaoMi/soar/database"
	"github.com/XiaoMi/soar/env"

	"github.com/kr/pretty"
	"github.com/percona/go-mysql/query"
)

func Run(sqlCommand string) (*Output, error) {
	// 全局变量
	var err error
	var sql string         // 单条评审指定的 sql 或 explain
	var currentDB string   // 当前 SQL 使用的 database
	sqlCounter := 1        // SQL 计数器
	lineCounter := 1       // 行计数器
	var alterSQLs []string // 待评审的 SQL 中所有 ALTER 请求
	// alterTableTimes := make(map[string]int)                   // 待评审的 SQL 中同一经表 ALTER 请求计数器
	suggestMerged := make(map[string]map[string]advisor.Rule) // 优化建议去重, key 为 sql 的 fingerprint.ID
	var suggestStr []string                                   // string 形式格式化之后的优化建议，用于 -report-type json
	tables := make(map[string][]string)                       // SQL 使用的库表名

	// config init
	common.Config.LogOutput = "console"
	common.Config.ReportType = "json"

	// 环境初始化，连接检查线上环境+构建测试环境
	// vEnv, rEnv := env.BuildEnv()

	// 读入待优化 SQL ，当配置文件或命令行参数未指定 SQL 时从管道读取
	// buf := initQuery(common.Config.Query)
	buf := sqlCommand

	lineCounter += ast.LeftNewLines([]byte(buf))
	buf = strings.TrimSpace(buf)

	// remove bom from file header
	var bom []byte
	buf, bom = common.RemoveBOM([]byte(buf))

	if isContinue, exitCode := reportTool(buf, bom); !isContinue {
		os.Exit(exitCode)
	}

	// 逐条SQL给出优化建议
	for ; ; sqlCounter++ {
		var id string                                     // fingerprint.ID
		heuristicSuggest := make(map[string]advisor.Rule) // 启发式建议
		expSuggest := make(map[string]advisor.Rule)       // EXPLAIN 解读
		idxSuggest := make(map[string]advisor.Rule)       // 索引建议
		proSuggest := make(map[string]advisor.Rule)       // Profiling 信息
		traceSuggest := make(map[string]advisor.Rule)     // Trace 信息
		mysqlSuggest := make(map[string]advisor.Rule)     // MySQL 返回的 ERROR 信息

		if buf == "" {
			common.Log.Debug("Ending, buf: '%s', sql: '%s'", buf, sql)
			break
		}
		// 查询请求切分
		orgSQL, sql, bufBytes := ast.SplitStatement([]byte(buf), []byte(common.Config.Delimiter))
		// lineCounter
		lc := ast.NewLines([]byte(orgSQL))
		// leftLineCounter
		llc := ast.LeftNewLines([]byte(orgSQL))
		lineCounter += llc
		if len(buf) == len(bufBytes) {
			// 防止切分死循环，当剩余的内容和原 SQL 相同时直接清空 buf
			buf = ""
			orgSQL = string(bufBytes)
			sql = orgSQL
		} else {
			buf = string(bufBytes)
		}

		// 去除无用的备注和空格
		sql = database.RemoveSQLComments(sql)
		if sql == "" {
			common.Log.Debug("empty query or comment, buf: %s", buf)
			continue
		}
		common.Log.Debug("main loop SQL: %s", sql)

		// +++++++++++++++++++++小工具集[开始]+++++++++++++++++++++++{
		fingerprint := strings.TrimSpace(query.Fingerprint(sql))
		// SQL 签名
		id = query.Id(fingerprint)
		currentDB = env.CurrentDB(sql, currentDB)
		switch common.Config.ReportType {
		case "fingerprint":
			// SQL 指纹
			if common.Config.Verbose {
				fmt.Printf("-- ID: %s\n", id)
			}
			fmt.Println(fingerprint)
			continue
		case "pretty":
			// SQL 美化
			fmt.Println(ast.Pretty(sql, "builtin") + common.Config.Delimiter)
			continue
		case "compress":
			// SQL 压缩
			fmt.Println(ast.Compress(sql) + common.Config.Delimiter)
			continue
		case "ast":
			// print vitess AST data struct
			ast.PrintPrettyVitessStmtNode(sql)
			continue
		case "ast-json":
			// print vitess SQL AST into json format
			fmt.Println(ast.VitessStmtNode2JSON(sql))
			continue
		case "tiast":
			// print TiDB AST data struct
			ast.PrintPrettyStmtNode(sql, "", "")
			continue
		case "tiast-json":
			// print TiDB SQL AST into json format
			fmt.Println(ast.StmtNode2JSON(sql, "", ""))
			continue
		case "tokenize":
			// SQL 切词
			_, err = pretty.Println(ast.Tokenize(sql))
			common.LogIfWarn(err, "")
			continue
		default:
			// 建议去重，减少评审整个文件耗时
			// TODO: 由于 a = 11 和 a = '11' 的 fingerprint 相同，这里一旦跳过即无法检查有些建议了，如： ARG.003
			if _, ok := suggestMerged[id]; ok {
				// `use ?` 不可以去重，去重后将导致无法切换数据库
				if !strings.HasPrefix(fingerprint, "use") {
					continue
				}
			}
			// 黑名单中的SQL不给建议
			if advisor.InBlackList(fingerprint) {
				// `use ?` 不可以出现在黑名单中
				if !strings.HasPrefix(fingerprint, "use") {
					continue
				}
			}
		}
		tables[id] = ast.SchemaMetaInfo(sql, currentDB)
		// +++++++++++++++++++++小工具集[结束]+++++++++++++++++++++++}

		// +++++++++++++++++++++语法检查[开始]+++++++++++++++++++++++{
		q, syntaxErr := advisor.NewQuery4Audit(sql)
		// stmt := q.Stmt
		if syntaxErr != nil {
			return nil, syntaxErr
		}

		// +++++++++++++++++++++启发式规则建议[开始]+++++++++++++++++++++++{
		common.Log.Debug("start of heuristic advisor Query: %s", q.Query)
		for item, rule := range advisor.HeuristicRules {
			// 去除忽略的建议检查
			okFunc := (*advisor.Query4Audit).RuleOK
			if !advisor.IsIgnoreRule(item) && &rule.Func != &okFunc {
				r := rule.Func(q)
				if r.Item == item {
					heuristicSuggest[item] = r
				}
			}
		}
		common.Log.Debug("end of heuristic advisor Query: %s", q.Query)

		// +++++++++++++++++++++打印单条 SQL 优化建议[开始]++++++++++++++++++++++++++{
		common.Log.Debug("start of print suggestions, Query: %s", q.Query)
		if strings.HasPrefix(fingerprint, "use") {
			continue
		}
		sug, str := advisor.FormatSuggest(q.Query, currentDB, common.Config.ReportType, heuristicSuggest, idxSuggest, expSuggest, proSuggest, traceSuggest, mysqlSuggest)
		suggestMerged[id] = sug
		switch common.Config.ReportType {
		case "json":
			suggestStr = append(suggestStr, str)
		case "tables":
		case "duplicate-key-checker":
		case "rewrite":
		case "lint":
			for _, s := range strings.Split(str, "\n") {
				// ignore empty output
				if strings.TrimSpace(s) == "" {
					continue
				}

				if common.Config.Query != "" {
					if _, err = os.Stat(common.Config.Query); err == nil {
						fmt.Printf("%s:%d:%s\n", common.Config.Query, lineCounter, s)
					} else {
						fmt.Printf("null:%d:%s\n", lineCounter, s)
					}
				} else {
					fmt.Printf("stdin:%d:%s\n", lineCounter, s)
				}
			}
			lineCounter += lc - llc
		case "html":
			fmt.Println(common.Markdown2HTML(str))
		default:
			fmt.Println(str)
		}
		common.Log.Debug("end of print suggestions, Query: %s", q.Query)
		// +++++++++++++++++++++打印单条 SQL 优化建议[结束]++++++++++++++++++++++++++}
	}

	// 同一张表的多条 ALTER 语句合并为一条
	if ast.RewriteRuleMatch("mergealter") {
		for _, v := range ast.MergeAlterTables(alterSQLs...) {
			fmt.Println(strings.TrimSpace(v))
		}
		return nil, nil
	}

	// 以 JSON 格式化输出
	var output Output
	if common.Config.ReportType == "json" && len(suggestStr) > 0 {
		if err := json.Unmarshal([]byte(suggestStr[0]), &output); err != nil {
			return nil, err
		}

		// fmt.Println("[\n", strings.Join(suggestStr, ",\n"), "\n]")
	}

	return &output, nil
}
