#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h> 
#include <string.h>

static int callback(void *NotUsed, int argc, char **argv, char **azColName){
    int i;
    for(i=0; i<argc; i++){
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

int main(int argc, char* argv[])
{
    sqlite3 *db=0;
    char *zErrMsg = 0;

    /* Open database */
    int rc = sqlite3_open("test.db", &db);
    if( rc ){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(0);
    }else{
        fprintf(stdout, "Opened database successfully\n");
    }

    /* Create SQL statement */
    const char *sql = "CREATE TABLE connections ("
        "starttime TEXT NOT NULL,"
        "endtime TEXT NOT NULL,"
        "src_ipn TEXT,"  
        "dst_ipn TEXT,"
        "mac_daddr TEXT,"
        "mac_saddr TEXT,"
        "packets INTEGER,"
        "srcport INTEGER,"
        "dstport INTEGER,"
        "hashdigest_md5 TEXT);";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
    if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return 0;
    }
    fprintf(stdout, "Table created successfully\n");

    const char* zSql = "INSERT INTO connections (starttime,endtime,src_ipn,dst_ipn,mac_daddr,mac_saddr,packets,srcport,dstport,hashdigest_md5) VALUES (?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt *s=0;
    if(sqlite3_prepare_v2(db, zSql, strlen(zSql), &s, NULL)!=SQLITE_OK ){
        fprintf(stderr, "SQL prepare error");
        return(0);
    }
    for(int i=0;i<1000;i++){
        char buf[30];
        strcpy(buf,"1990-10-10T12:12:12");
        if(sqlite3_bind_text(s,1,buf,strlen(buf),SQLITE_TRANSIENT)!=SQLITE_OK){
            fprintf(stderr,"bind3 fails");
            exit(1);
        }
        strcpy(buf,"1990-10-10T13:00:00");
        if(sqlite3_bind_text(s,2,buf,strlen(buf),SQLITE_TRANSIENT)!=SQLITE_OK){
            fprintf(stderr,"bind3 fails");
            exit(1);
        }
        snprintf(buf,sizeof(buf),"%d.%d.%d.%d",i%256,i%256,i%256,i%256);
        if(sqlite3_bind_text(s,3,buf,strlen(buf),SQLITE_TRANSIENT)!=SQLITE_OK){
            fprintf(stderr,"bind3 fails");
            exit(1);
        }
        snprintf(buf,sizeof(buf),"%d.%d.%d.%d",1,2,3,4);
        if(sqlite3_bind_text(s,4,buf,strlen(buf),SQLITE_TRANSIENT)!=SQLITE_OK){
            fprintf(stderr,"bind4 fails");
            exit(1);
        }
        rc = sqlite3_step(s);
        if(rc==SQLITE_ERROR){
            fprintf(stderr,"sqlite3_step error???");
            exit(1);
        }
        sqlite3_reset(s);
        printf("i=%d\n",i);
    }
    if(sqlite3_finalize(s)!=SQLITE_OK){
        fprintf(stderr,"sqlite3_finalize failed\n");
        exit(1);
    }
    sqlite3_free(db);
}
