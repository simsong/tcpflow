/*
 * Feature recorder mods for writing features into an SQLite3 database.
 */

/* http://blog.quibb.org/2010/08/fast-bulk-inserts-into-sqlite/ */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sbuf.h>

#include "bulk_extractor_i.h"
#include "histogram.h"

/*
 * Time results with ubnist1 on R4:
 * no SQL - 79 seconds
 * no pragmas - 651 seconds
 * "PRAGMA synchronous =  OFF", - 146 second
 * "PRAGMA synchronous =  OFF", "PRAGMA journal_mode=MEMORY", - 79 seconds
 *
 * Time with domexusers:
 * no SQL - 
 */


#if defined(HAVE_LIBSQLITE3) && defined(HAVE_SQLITE3_H)
#define USE_SQLITE3 
#endif
#define SQLITE_EXTENSION ".sqlite"

#ifndef SQLITE_DETERMINISTIC
#define SQLITE_DETERMINISTIC 0
#endif

static int debug  = 0;

#ifdef USE_SQLITE3
static const char *schema_db[] = {
    "PRAGMA synchronous =  OFF", 
    "PRAGMA journal_mode=MEMORY",
    //"PRAGMA temp_store=MEMORY",  // did not improve performance
    "PRAGMA cache_size = 200000", 
    "CREATE TABLE IF NOT EXISTS db_info (schema_ver INTEGER, bulk_extractor_ver INTEGER)",
    "INSERT INTO  db_info (schema_ver, bulk_extractor_ver) VALUES (1,1)",
    "CREATE TABLE IF NOT EXISTS be_features (tablename VARCHAR,comment TEXT)",
    "CREATE TABLE IF NOT EXISTS be_config (name VARCHAR,value VARCHAR)",
    0};

/* Create a feature table and note that it has been created in be_features */
static const char *schema_tbl[] = {
    "CREATE TABLE IF NOT EXISTS f_%s (offset INTEGER(12), path VARCHAR, feature_eutf8 TEXT, feature_utf8 TEXT, context_eutf8 TEXT)",
    "CREATE INDEX IF NOT EXISTS f_%s_idx1 ON f_%s(offset)",
    "CREATE INDEX IF NOT EXISTS f_%s_idx2 ON f_%s(feature_eutf8)",
    "CREATE INDEX IF NOT EXISTS f_%s_idx3 ON f_%s(feature_utf8)",
    "INSERT INTO be_features (tablename,comment) VALUES ('f_%s','')",
    0};

/* This creates the base histogram. Note that the SQL fails if the histogram exists */
static const char *schema_hist[] = {
    "CREATE TABLE h_%s (count INTEGER(12), feature_utf8 TEXT)",
    "CREATE INDEX h_%s_idx1 ON h_%s(count)",
    "CREATE INDEX h_%s_idx2 ON h_%s(feature_utf8)",
    0};

/* This performs the histogram operation */
static const char *schema_hist1[] = {
    "INSERT INTO h_%s select COUNT(*),feature_utf8 from f_%s GROUP BY feature_utf8",
    0};

#ifdef HAVE_SQLITE3_CREATE_FUNCTION_V2
static const char *schema_hist2[] = {
    "INSERT INTO h_%s select sum(count),BEHIST(feature_utf8) from h_%s where BEHIST(feature_utf8)!='' GROUP BY BEHIST(feature_utf8)",
    0};
#endif

#endif
const char *feature_recorder::db_insert_stmt = "INSERT INTO f_%s (offset,path,feature_eutf8,feature_utf8,context_eutf8) VALUES (?1, ?2, ?3, ?4, ?5)";
static const char *begin_transaction[] = {"BEGIN TRANSACTION",0};
static const char *commit_transaction[] = {"COMMIT TRANSACTION",0};
void feature_recorder::besql_stmt::insert_feature(const pos0_t &pos,
                                                        const std::string &feature,
                                                        const std::string &feature8, const std::string &context)
{
#ifdef USE_SQLITE3
    assert(stmt!=0);
    cppmutex::lock lock(Mstmt);           // grab a lock
    const std::string &path = pos.str();
    sqlite3_bind_int64(stmt, 1, pos.imageOffset()); // offset
    sqlite3_bind_text(stmt, 2, path.data(), path.size(), SQLITE_STATIC); // path
    sqlite3_bind_text(stmt, 3, feature.data(), feature.size(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, feature8.data(), feature8.size(), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, context.data(), context.size(), SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr,"sqlite3_step failed\n");
    }
    sqlite3_reset(stmt);
#endif
};

feature_recorder::besql_stmt::besql_stmt(BEAPI_SQLITE3 *db3,const char *sql):Mstmt(),stmt()
{
#ifdef USE_SQLITE3
    assert(db3!=0);
    assert(sql!=0);
    sqlite3_prepare_v2(db3,sql, strlen(sql), &stmt, NULL);
    assert(stmt!=0);
#endif
}

feature_recorder::besql_stmt::~besql_stmt()
{
#ifdef USE_SQLITE3
    assert(stmt!=0);
    sqlite3_finalize(stmt);
    stmt = 0;
#endif
}

void feature_recorder_set::db_send_sql(BEAPI_SQLITE3 *db,const char **stmts, ...)
{
#ifdef USE_SQLITE3
    assert(db!=0);
    for(int i=0;stmts[i];i++){
        char *errmsg = 0;
        char buf[65536];

        va_list ap;
        va_start(ap,stmts);
        vsnprintf(buf,sizeof(buf),stmts[i],ap);
        va_end(ap);
        if(debug) std::cerr << "SQL: " << buf << "\n";
        // Don't error on a PRAGMA
        if((sqlite3_exec(db,buf,NULL,NULL,&errmsg) != SQLITE_OK)  && (strncmp(buf,"PRAGMA",6)!=0)) {
            fprintf(stderr,"Error executing '%s' : %s\n",buf,errmsg);
            exit(1);
        }
    }
#endif
}

void feature_recorder_set::db_create_table(const std::string &name)
{
#ifdef USE_SQLITE3
    assert(name.size()>0);
    db_send_sql(db3,schema_tbl,name.c_str(),name.c_str());
#endif
}

BEAPI_SQLITE3 *feature_recorder_set::db_create_empty(const std::string &name)
{
#ifdef USE_SQLITE3
    assert(name.size()>0);
    std::string dbfname  = outdir + "/" + name +  SQLITE_EXTENSION;
    if(debug) std::cerr << "create_feature_database " << dbfname << "\n";
    BEAPI_SQLITE3 *db=0;
    if (sqlite3_open_v2(dbfname.c_str(), &db,
                        SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX,
                        0)!=SQLITE_OK) {
        std::cerr << "Cannot create database '" << dbfname << "': " << sqlite3_errmsg(db) << "\n";
        sqlite3_close(db);
        exit(1);
    }
    return db;
#else
    return 0;
#endif
}

#pragma GCC diagnostic ignored "-Wmissing-noreturn"
void feature_recorder_set::db_create()
{
#ifdef USE_SQLITE3
    assert(db3==0);
    db3 = db_create_empty("report");
    db_send_sql(db3,schema_db);
#else
    std::cerr << "*** CANNOT CREATE SQLITE3 DATABASE ***\n";
    std::cerr << "*** Compiled without libsqlite     ***\n";
    assert(0 && debug);                 // prevent debug from being not used
#endif
}

void feature_recorder_set::db_close()
{
#ifdef USE_SQLITE3
    if(db3){
        if(debug) std::cerr << "db_close()\n";
        sqlite3_close(db3);
        db3 = 0;
    }
#endif
}

void feature_recorder_set::db_transaction_begin()
{
    cppmutex::lock lock(Min_transaction);
    if(!in_transaction){
        db_send_sql(db3,begin_transaction);
        in_transaction = true;
    }
}

void feature_recorder_set::db_transaction_commit()
{
    cppmutex::lock lock(Min_transaction);
    if(in_transaction){
        db_send_sql(db3,commit_transaction);
        in_transaction = false;
    } else {
        std::cerr << "No transaction to commit\n";
    }
}

/* Hook for writing feature to SQLite3 database */
void feature_recorder::db_write0(const pos0_t &pos0,const std::string &feature,const std::string &context)
{
    /**
     * Note: this is not very efficient, passing through a quoted feature and then unquoting it.
     * We could make this more efficient.
     */
    std::string *feature8 = HistogramMaker::convert_utf16_to_utf8(feature_recorder::unquote_string(feature));
    assert(bs!=0);
    bs->insert_feature(pos0,feature,
                         feature8 ? *feature8 : feature,
                         flag_set(feature_recorder::FLAG_NO_CONTEXT) ? "" : context);
    if (feature8) delete feature8;
}

/* Hook for writing histogram
 */
#ifdef USE_SQLITE3
static int callback_counter(void *param, int argc, char **argv, char **azColName)
{
    int *counter = reinterpret_cast<int *>(param);
    (*counter)++;
    return 0;
}

#ifdef HAVE_SQLITE3_CREATE_FUNCTION_V2
static void behist(sqlite3_context *ctx,int argc,sqlite3_value**argv)
{
    const histogram_def *def = reinterpret_cast<const histogram_def *>(sqlite3_user_data(ctx));
    if(debug) std::cerr << "behist feature=" << def->feature << "  suffix="
                        << def->suffix << "  argc=" << argc << "value = " << sqlite3_value_text(argv[0]) << "\n";
    std::string new_feature(reinterpret_cast<const char *>(sqlite3_value_text(argv[0])));
    if (def->reg.search(new_feature,&new_feature,0,0)) {
        sqlite3_result_text(ctx,new_feature.c_str(),new_feature.size(),SQLITE_TRANSIENT);
    }
}
#endif
#endif

void feature_recorder::dump_histogram_db(const histogram_def &def,void *user,feature_recorder::dump_callback_t cb) const
{
#ifdef USE_SQLITE3
    /* First check to see if there exists a feature histogram summary. If not, make it */
    std::string query = "SELECT name FROM sqlite_master WHERE type='table' AND name='h_" + def.feature +"'";
    char *errmsg=0;
    int rowcount=0;
    if (sqlite3_exec(fs.db3,query.c_str(),callback_counter,&rowcount,&errmsg)){
        std::cerr << "sqlite3: " << errmsg << "\n";
        return;
    }
    if (rowcount==0){
        const char *feature = def.feature.c_str();
        fs.db_send_sql(fs.db3,schema_hist, feature, feature); // creates the histogram
        fs.db_send_sql(fs.db3,schema_hist1, feature, feature); // creates the histogram
    }
#ifdef HAVE_SQLITE3_CREATE_FUNCTION_V2
    /* Now create the summarized histogram for the regex, if it is not existing, but only if we have
     * sqlite3_create_function_v2
     */
    if (def.pattern.size()>0){
        /* Create the database where we will add the histogram */
        std::string hname = def.feature + "_" + def.suffix;

        /* Remove any "-" characters if present */
        for(size_t i=0;i<hname.size();i++){
            if (hname[i]=='-') hname[i]='_';
        }

        if(debug) std::cerr << "CREATING TABLE = " << hname << "\n";
        if (sqlite3_create_function_v2(fs.db3,"BEHIST",1,SQLITE_UTF8|SQLITE_DETERMINISTIC,
                                       (void *)&def,behist,0,0,0)) {
            std::cerr << "could not register function BEHIST\n";
            return;
        }
        const char *fn = def.feature.c_str();
        const char *hn = hname.c_str();
        fs.db_send_sql(fs.db3,schema_hist, hn , hn); // create the table
        fs.db_send_sql(fs.db3,schema_hist2, hn , fn); // select into it from a function of the old histogram table

        /* erase the user defined function */
        if (sqlite3_create_function_v2(fs.db3,"BEHIST",1,SQLITE_UTF8|SQLITE_DETERMINISTIC,
                                       (void *)&def,0,0,0,0)) {
            std::cerr << "could not remove function BEHIST\n";
            return;
        }
    }
#endif
#endif
}

#ifdef STAND
static std::string hash_name("md5");
static std::string hash_func(const uint8_t *buf,size_t bufsize)
{
    if(hash_name=="md5" || hash_name=="MD5"){
        return md5_generator::hash_buf(buf,bufsize).hexdigest();
    }
    if(hash_name=="sha1" || hash_name=="SHA1" || hash_name=="sha-1" || hash_name=="SHA-1"){
        return sha1_generator::hash_buf(buf,bufsize).hexdigest();
    }
    if(hash_name=="sha256" || hash_name=="SHA256" || hash_name=="sha-256" || hash_name=="SHA-256"){
        return sha256_generator::hash_buf(buf,bufsize).hexdigest();
    }
    std::cerr << "Invalid hash name: " << hash_name << "\n";
    std::cerr << "This version of bulk_extractor only supports MD5, SHA1, and SHA256\n";
    exit(1);
}
static feature_recorder_set::hash_def my_hasher(hash_name,hash_func);

feature_recorder_set::feature_recorder_set(uint32_t flags_,const feature_recorder_set::hash_def &hasher_):
    flags(flags_),seen_set(),input_fname(),
    outdir(),
    frm(),
    histogram_defs(),
    db3(),
    alert_list(),stop_list(),
    scanner_stats(),hasher(hasher_)
{
}

feature_recorder *feature_recorder_set::create_name_factory(const std::string &name_){return 0;}
void feature_recorder_set::create_name(const std::string &name,bool create_stop_also){}
bool feature_recorder_set::check_previously_processed(const uint8_t *buf,size_t bufsize){return 0;}
feature_recorder *feature_recorder_set::get_name(const std::string &name) const{return 0;}
feature_recorder *feature_recorder_set::get_alert_recorder() const{return 0;}
void feature_recorder_set::get_feature_file_list(std::vector<std::string> &ret){}

int main(int argc,char **argv)
{
    const char *dbfile = "test.sql3";
    char *errmsg = 0;
    sqlite3 *db=0;

    feature_recorder_set fs(0,my_hasher);

    unlink(dbfile);
    fs.db_create();
    if(1){
        /* Create an email table */
        fs.db_create_table("email");
        
        /* Lets throw a million features into the table as a test */
        //sqlite3_exec(db,"BEGIN TRANSACTION",NULL,NULL,&errmsg);
        beapi_sql_stmt s(db,"email");
        for(int i=0;i<1000000;i++){
            pos0_t p;
            pos0_t p1 = p+i;
            
            if(i%10000==0) printf("i=%d\n",i);
            
            char feature[64];
            snprintf(feature,sizeof(feature),"user%d@company.com",i);
            char context[64];
            snprintf(context,sizeof(context),"this is the context user%d@company.com yes it is!",i);
            //insert_statement(stmt,p1,feature,context);
        }
        //sqlite3_exec(db,"COMMIT TRANSACTION",NULL,NULL,&errmsg);
    }
    fs.db_close();
}
#endif

