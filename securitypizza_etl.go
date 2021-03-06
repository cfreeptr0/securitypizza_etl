package main

import (
	"bufio"
	"context"
	"encoding/ascii85"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v4/pgxpool"
)

const (
	BATCH_SIZE          = 60_000
	DATE_FORMAT         = "January 2 2006"
	HIBP_TABLE_SCHEMA   = `CREATE TABLE IF NOT EXISTS hibp (hibp_id CHAR(25) NOT NULL PRIMARY KEY, password VARCHAR(150))`
	IMPORT_TABLE_SCHEMA = `CREATE TABLE IF NOT EXISTS imports (import_id serial PRIMARY KEY, name VARCHAR(200) NOT NULL, state VARCHAR(50) NOT NULL, import_date DATE NOT NULL)`
)

type hibpPasswordData struct {
	hash     string
	password string
}

func dbVersion(connectionString string) string {
	var dbVersion string
	dbPool, err := pgxpool.Connect(context.Background(), connectionString)
	if err != nil {
		log.Fatal(err)
	}
	defer dbPool.Close()

	err = dbPool.QueryRow(context.Background(), "SELECT version()").Scan(&dbVersion)
	if err != nil {
		log.Fatal(err)
	}
	return dbVersion
}

func stringToDate(date string) time.Time {
	if date == "" {
		log.Fatal("Missing required date field e.g. November 19 2020")
	}

	time, err := time.Parse(DATE_FORMAT, date)
	if err != nil {
		log.Fatal(err)

	}
	log.Printf("File import time %s", time)
	return time
}

func hibpEtl(connectionString, filename, date string) int {
	var count int
	var errors int
	rowData := make([]string, 0, BATCH_SIZE)

	time := stringToDate(date)

	log.Printf("HIBP Processing file %s for %s", filename, date)

	dbPool, err := pgxpool.Connect(context.Background(), connectionString)
	if err != nil {
		log.Fatal(err)
	}
	defer dbPool.Close()

	dbSchemaCreate(dbPool, HIBP_TABLE_SCHEMA)
	dbSchemaCreate(dbPool, IMPORT_TABLE_SCHEMA)

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		data := strings.SplitN(s.Text(), ":", 2)
		if len(data) != 2 {
			errors++
			continue
		}
		hash, err := hex.DecodeString(data[0])
		if err != nil {
			errors++
			continue
		}
		hibpLen := ascii85.MaxEncodedLen(len(hash))
		hibp_id := make([]byte, hibpLen)

		bytesWritten := ascii85.Encode(hibp_id, hash)
		hibp := string(hibp_id[0:bytesWritten])
		if !utf8.ValidString(hibp) {
			log.Fatal("Warning not a string %v", hibp)
		}
		count++
		rowData = append(rowData, hibp)
		if count%BATCH_SIZE == 0 {
			log.Printf("processing %d...", count)
			errors += hibpProcessRowDataBatch(dbPool, rowData)
			rowData = make([]string, 0, BATCH_SIZE)
		}
	}
	err = s.Err()
	if err != nil {
		log.Fatal(err)
	}
	errors += hibpProcessRowDataBatch(dbPool, rowData)

	var state string
	if errors > 0 {
		log.Printf("%d Error(s) found", errors)
		state = "error"
	} else {
		state = "done"
	}

	dbLogImportData(dbPool, "pwned-passwords-sha1", state, time)

	return count
}

func hibpProcessRowDataBatch(dbPool *pgxpool.Pool, rowData []string) int {
	var errors int
	values := []string{}
	args := []interface{}{}

	for i, row := range rowData {
		values = append(values, fmt.Sprintf("($%d)", i+1))
		args = append(args, row)
	}
	query := fmt.Sprintf("INSERT INTO hibp (hibp_id) VALUES %s ON CONFLICT (hibp_id) DO NOTHING",
		strings.Join(values, ","))
	_, err := dbPool.Exec(context.Background(), query, args...)
	if err != nil {
		log.Printf("Err: %v on %s: %v", err, query, args)
		errors++
	}
	return errors
}

func hibpPasswordsEtl(connectionString, filename, date string) int {
	var count int
	var errors int
	rowData := make([]hibpPasswordData, 0, BATCH_SIZE)
	time := stringToDate(date)

	log.Printf("HIBP Passwords Processing file %s for %s", filename, date)

	dbPool, err := pgxpool.Connect(context.Background(), connectionString)
	if err != nil {
		log.Fatal(err)
	}
	defer dbPool.Close()

	dbSchemaCreate(dbPool, HIBP_TABLE_SCHEMA)
	dbSchemaCreate(dbPool, IMPORT_TABLE_SCHEMA)

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		data := strings.SplitN(s.Text(), ":", 2)
		if len(data) != 2 {
			errors++
			continue
		}
		hash := strings.ToLower(data[0])
		password := data[1]
		count++

		row := hibpPasswordData{hash, password}
		rowData = append(rowData, row)

		if count%BATCH_SIZE == 0 {
			log.Printf("processing %d...", count)
			errors += hibpPasswordProcessRowDataBatch(rowData, dbPool)
			rowData = make([]hibpPasswordData, 0, BATCH_SIZE)
		}
	}
	err = s.Err()
	if err != nil {
		log.Fatal(err)
	}
	errors += hibpPasswordProcessRowDataBatch(rowData, dbPool)

	var state string
	if errors > 0 {
		log.Printf("%d Error(s) found", errors)
		state = "error"
	} else {
		state = "done"
	}
	dbLogImportData(dbPool, "pwned-passwords-plain", state, time)

	return count
}

func hibpPasswordProcessRowDataBatch(rowData []hibpPasswordData, dbPool *pgxpool.Pool) int {
	var errors int
	values := []string{}
	args := []interface{}{}

	for i, row := range rowData {
		values = append(values, fmt.Sprintf("($%d, $%d)", i*2+1, i*2+2))
		args = append(args, row.hash)
		args = append(args, row.password)
	}
	query := fmt.Sprintf("INSERT INTO hibp (hibp_id, password) VALUES %s ON CONFLICT (hibp_id) DO UPDATE SET password = EXCLUDED.password",
		strings.Join(values, ","))
	_, err := dbPool.Exec(context.Background(), query, args...)
	if err != nil {
		log.Printf("Err: %v on %s", err, query)
		errors++
	}
	return errors
}

func dbLogImportData(dbPool *pgxpool.Pool, name, state string, time time.Time) {
	query := "INSERT INTO imports (name, state, import_date) VALUES ($1, $2, $3)"
	_, err := dbPool.Exec(context.Background(), query, name, state, time)
	if err != nil {
		log.Printf("Error writing to imports: %v", err)
	}

}

func dbSchemaCreate(dbPool *pgxpool.Pool, idempotentSchema string) {
	_, err := dbPool.Exec(context.Background(), idempotentSchema)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	dbConnectionString := os.Getenv("DATABASEURL")
	if dbConnectionString == "" {
		log.Fatalf("Missing env DATABASEURL")
	}

	hibpFile := flag.String("hibp-file", "", "pwned-passwords-sha1-ordered-by-hash-v?.txt")
	hibpDate := flag.String("hibp-date", "", "Date from https://haveibeenpwned.com/Passwords e.g. November 19 2020")
	hibpPasswordsFile := flag.String("hibp-passwords-file", "", "8161_have-i-been-pwned-v7_found_hash_plain.txt")
	flag.Parse()

	log.Printf("Connecting to PG: %s\n", dbVersion(dbConnectionString))
	if *hibpFile != "" {
		log.Printf("hibp import %d records", hibpEtl(dbConnectionString, *hibpFile, *hibpDate))
	}
	if *hibpPasswordsFile != "" {
		log.Printf("hibp passwords import %d", hibpPasswordsEtl(dbConnectionString, *hibpPasswordsFile, *hibpDate))
	}
}
