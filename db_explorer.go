package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

//
// Meta
//
type RecordMeta struct {
	Field    string
	Type     string
	Nullable bool
	Length   int
	isPk     bool
}

//
// HTTP Api
//
type Tables struct {
	Result interface{} `json:"tables,omitempty"`
}

type Records struct {
	Result []map[string]interface{} `json:"records,omitempty"`
}
type Record struct {
	Result map[string]interface{} `json:"record,omitempty"`
}
type ApiResponse struct {
	Error  string      `json:"error,omitempty"`
	Result interface{} `json:"response,omitempty"`
}

//
// Web
//
type HTTPRequest struct {
	params  map[string]string
	paths   []string
	subPath string
	method  string
	payload []byte
}

func (r HTTPRequest) limit() int {
	p, ok := r.params["limit"]
	if ok {
		limit, err := strconv.Atoi(p)
		if err == nil {
			return limit
		}
	}
	return 1000
}

func (r HTTPRequest) offset() int {
	p, ok := r.params["offset"]
	if ok {
		offset, err := strconv.Atoi(p)
		if err == nil {
			return offset
		}
	}
	return 0
}

func (r HTTPRequest) justRoot() bool {
	return len(r.paths) > 1 && r.paths[1] == ""
}

func (r HTTPRequest) hasTable() bool {
	return len(r.paths) > 1 && r.paths[1] != ""
}

func (r HTTPRequest) hasId() bool {
	return len(r.paths) > 2 && r.paths[2] != ""
}

func (r HTTPRequest) getTable() string {
	return r.paths[1]
}

func (r HTTPRequest) getId() int {
	id, _ := strconv.Atoi(r.paths[2])
	return id
}

func Parse(request *http.Request) HTTPRequest {
	req := HTTPRequest{}
	req.params = make(map[string]string)
	req.paths = strings.Split(request.URL.Path, "/")
	req.method = request.Method

	bytes, err := ioutil.ReadAll(request.Body)
	if err == nil {
		req.payload = bytes
	}

	rawParams := strings.Split(request.RequestURI, "?")

	if len(rawParams) > 1 && rawParams[1] != "" {
		for _, pair := range strings.Split(rawParams[1], "&") {
			kv := strings.Split(pair, "=")
			req.params[kv[0]] = kv[1]
		}
	}

	return req
}

// тут вы пишете код
// обращаю ваше внимание - в этом задании запрещены глобальные переменные
type QueryRunner struct {
	db *sql.DB
}

func (qr *QueryRunner) runQuery(query string, h func(*sql.Rows) error) error {
	rows, err := qr.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		err := h(rows)
		if err != nil {
			return err
		}
	}
	err = rows.Err()
	if err != nil {
		return err
	}

	return nil
}

type DbExplorer struct {
	db      *sql.DB
	fetcher *DataFetcher
	runner  *QueryRunner
}

type DataFetcher struct {
	db     *sql.DB
	runner *QueryRunner
	tables []string
	meta   map[string][]RecordMeta
	ids    map[string]string
}

func (f *DataFetcher) findById(table string, id int) (map[string]interface{}, error) {
	result, e := f.query(table, fmt.Sprintf("SELECT * FROM %s where %s=%d", table, f.ids[table], id))

	if e != nil {
		return nil, e
	}

	if len(result) != 1 {
		return nil, errors.New(fmt.Sprintf("not found by %d", id))
	}

	return result[0], nil
}

func (f *DataFetcher) findAll(table string, offset int, limit int) ([]map[string]interface{}, error) {
	return f.query(table, fmt.Sprintf("SELECT * FROM %s limit %d offset %d", table, limit, offset))
}

func (f *DataFetcher) update(table string, id int, values map[string]interface{}) (int64, error) {
	fields := make([]string, 0)
	vals := make([]interface{}, 0)
	placeholders := make([]string, 0)

	for field, v := range values {
		if field == f.ids[table] {
			return 0, errors.New(fmt.Sprintf("field %s have invalid type", f.ids[table]))
		}

		for _, m := range f.meta[table] {
			if m.Field == field {
				if !m.Nullable && v == nil {
					return 0, errors.New(fmt.Sprintf("field %s have invalid type", field))
				}

				// only int and string supported
				if v != nil && m.Type != reflect.TypeOf(v).String() {
					return 0, errors.New(fmt.Sprintf("field %s have invalid type", field))
				}
			}
		}

		fields = append(fields, field+"=?")
		vals = append(vals, v)
		placeholders = append(placeholders, "?")
	}

	update := fmt.Sprintf("UPDATE %s set %s WHERE %s=%d", table,
		strings.Join(fields, ","),
		f.ids[table],
		id,
	)

	stmt, err := f.db.Prepare(update)
	if err != nil {
		return 0, err
	}
	res, err := stmt.Exec(vals...)
	if err != nil {
		return 0, err
	}

	rowCnt, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	return rowCnt, nil
}

func (f *DataFetcher) delete(table string, id int) (int64, error) {
	deleteSt := fmt.Sprintf("DELETE FROM %s WHERE %s=?", table, f.ids[table])

	stmt, err := f.db.Prepare(deleteSt)
	if err != nil {
		return 0, err
	}
	res, err := stmt.Exec(id)
	if err != nil {
		return 0, err
	}

	rowCnt, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}

	return rowCnt, nil
}

func (f *DataFetcher) insert(table string, values map[string]interface{}) (int64, error) {
	fields := make([]string, 0)
	vals := make([]interface{}, 0)
	placeholders := make([]string, 0)

	for _, mt := range f.meta[table] {
		if !mt.Nullable {
			_, exists := values[mt.Field]
			// only strings are supported
			if !exists {
				values[mt.Field] = ""
			}
		}
	}

	for field, v := range values {
		if field == f.ids[table] {
			continue
		}
		found := false
		for _, mt := range f.meta[table] {
			if mt.Field == field {
				found = true
			}
		}
		if !found {
			continue
		}
		fields = append(fields, field)
		vals = append(vals, v)
		placeholders = append(placeholders, "?")
	}

	insert := fmt.Sprintf("INSERT INTO %s(%s) VALUES(%s)", table,
		strings.Join(fields, ","),
		strings.Join(placeholders, ","),
	)

	stmt, err := f.db.Prepare(insert)
	if err != nil {
		return 0, err
	}
	res, err := stmt.Exec(vals...)
	if err != nil {
		return 0, err
	}
	lastId, err := res.LastInsertId()
	if err != nil {
		log.Fatal(err)
	}
	return lastId, nil
}

func (f *DataFetcher) query(table string, q string) ([]map[string]interface{}, error) {
	meta, ok := f.meta[table]
	if !ok {
		return nil, errors.New("unknown table")
	}

	result := make([]map[string]interface{}, 0)

	e := f.runner.runQuery(q, func(rows *sql.Rows) error {
		colvals := make([]interface{}, len(meta))

		// handle more other types if needed
		for index, m := range meta {
			if m.Type == "int" {
				colvals[index] = new(int)
			} else {
				colvals[index] = new(sql.NullString)
			}
		}

		err := rows.Scan(colvals...)
		r := make(map[string]interface{}, 0)
		for index, colval := range colvals {
			nullString, ok := colval.(*sql.NullString)
			if ok {
				if nullString.Valid {
					r[meta[index].Field] = nullString.String
				} else {
					r[meta[index].Field] = nil
				}
			} else {
				r[meta[index].Field] = colval
			}
		}
		result = append(result, r)
		return err
	})
	if e != nil {
		return nil, e
	}
	return result, nil
}

func (f *DataFetcher) find(table string, id int) ([]map[string]interface{}, error) {
	m, ok := f.meta[table]
	if !ok {
		return nil, errors.New("unknown table")
	}
	colvals := make([]interface{}, len(m))
	for i, _ := range colvals {
		colvals[i] = new(interface{})
	}
	e := f.runner.runQuery(fmt.Sprintf("SELECT * FROM %s WHERE %s=%d", table, f.ids[table], id), func(rows *sql.Rows) error {
		return rows.Scan(colvals...)
	})
	if e != nil {
		return nil, e
	}
	return nil, nil
}

func (f *DataFetcher) updateMeta(table string, field sql.NullString, typ sql.NullString, nullable sql.NullString, isPk bool) {
	_, ok := f.meta[table]
	if !ok {
		f.meta[table] = make([]RecordMeta, 0)
	}

	meta := RecordMeta{
		field.String,
		extractGoType(typ.String),
		nullable.String == "YES",
		extractLen(typ.String),
		isPk,
	}

	f.meta[table] = append(f.meta[table], meta)
}

func NewDataFetcher(db *sql.DB, runner *QueryRunner) (*DataFetcher, error) {
	f := &DataFetcher{}
	f.runner = runner
	f.meta = make(map[string][]RecordMeta)
	f.db = db
	f.tables = make([]string, 0)
	f.ids = make(map[string]string)

	e := f.runner.runQuery("SHOW TABLES", func(rows *sql.Rows) error {
		var table string
		err := rows.Scan(&table)
		if err != nil {
			return err
		}
		f.tables = append(f.tables, table)
		return nil
	})

	if e != nil {
		return nil, e
	}

	for _, table := range f.tables {
		index := 0

		e = f.runner.runQuery("show fields from "+table, func(rows *sql.Rows) error {
			var field, typ, nullable, pk, g sql.NullString
			err := rows.Scan(&field, &typ, &nullable, &pk, &g, &g)
			if err != nil {
				return err
			}
			isPk := "PRI" == pk.String
			f.updateMeta(table, field, typ, nullable, isPk)
			if isPk {
				f.ids[table] = field.String
			}
			index = index + 1
			return nil
		})

		if e != nil {
			return nil, e
		}
	}

	return f, nil
}

func NewDbExplorer(db *sql.DB) (*DbExplorer, error) {
	runner := &QueryRunner{db}

	fetcher, err := NewDataFetcher(db, runner)
	if err != nil {
		return nil, err
	}
	return &DbExplorer{db, fetcher, runner}, nil
}

func (dex *DbExplorer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	parsed := Parse(request)

	if parsed.justRoot() {
		sendPayload(writer, Tables{dex.fetcher.tables})
		return
	}

	switch request.Method {
	case "GET":
		if parsed.hasTable() {
			for _, t := range dex.fetcher.tables {
				if t == parsed.getTable() {
					if parsed.hasId() {
						found, err := dex.fetcher.findById(t, parsed.getId())
						if err != nil {
							sendHttpError(writer, 404, "record not found")
							return
						}
						sendPayload(writer, Record{found})
						return
					} else {
						all, err := dex.fetcher.findAll(t, parsed.offset(), parsed.limit())
						if err != nil {
							sendError(writer, err)
							return
						}
						sendPayload(writer, Records{all})
						return
					}
				}
			}

			sendHttpError(writer, http.StatusNotFound, "unknown table")
			return
		}
		break

	case "POST":
		table := parsed.getTable()
		p := make(map[string]interface{})
		err := json.Unmarshal(parsed.payload, &p)
		if err != nil {
			sendError(writer, err)
			return
		}
		count, err := dex.fetcher.update(table, parsed.getId(), p)
		if err != nil {
			sendHttpError(writer, 400, err.Error())
			return
		}
		idHolder := make(map[string]int64)
		idHolder["updated"] = count
		sendPayload(writer, idHolder)
		return
	case "PUT":
		table := parsed.getTable()
		p := make(map[string]interface{})
		err := json.Unmarshal(parsed.payload, &p)
		if err != nil {
			sendError(writer, err)
			return
		}
		id, err := dex.fetcher.insert(table, p)
		if err != nil {
			sendError(writer, err)
			return
		}
		idHolder := make(map[string]int64)
		idHolder[dex.fetcher.ids[table]] = id
		sendPayload(writer, idHolder)
		return
	case "DELETE":
		id, err := dex.fetcher.delete(parsed.getTable(), parsed.getId())
		if err != nil {
			sendError(writer, err)
			return
		}
		idHolder := make(map[string]int64)
		idHolder["deleted"] = id
		sendPayload(writer, idHolder)
		return
	}

	sendHttpError(writer, http.StatusInternalServerError, "error")
}

func sendError(writer http.ResponseWriter, err error) {
	sendHttpError(writer, http.StatusInternalServerError, err.Error())
}

func sendHttpError(writer http.ResponseWriter, code int, description string) {
	writer.WriteHeader(code)
	data, _ := json.Marshal(ApiResponse{description, nil})
	writer.Write(data)
}

func sendPayload(writer http.ResponseWriter, payload interface{}) {
	data, _ := json.Marshal(ApiResponse{"", payload})
	writer.Write(data)
}

func toString(obj interface{}) string {
	switch reflect.TypeOf(obj).String() {
	case "string":
		return obj.(string)
		break
	case "int":
		return fmt.Sprintf("%d", obj.(int))
		break
	}

	return ""
}

func extractLen(typ string) int {
	var length int
	var compRegEx = regexp.MustCompile("(?i)varchar\\((\\d+)\\)")
	if match := compRegEx.FindStringSubmatch(typ); match != nil {
		length, _ = strconv.Atoi(match[1])
	}
	return length
}

// only int and string supported
func extractGoType(typ string) string {
	if strings.Contains(typ, "int") {
		return "int"
	}
	return "string"

}
