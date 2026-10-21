/* SPDX-License-Identifier: GPL-2.0+ */
/* Included after actual HTTP functions by recovery_security.py. */
static int checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static void setup(bool privileged)
{
    httpd_running=false; httpd_privileged=privileged;
    memset(&post_state,0,sizeof(post_state));
    job_kind=HTTP_JOB_NONE; job_state=HTTP_JOB_IDLE;
    downloads=replies=0; backup_ready=false; stop_requested=false;
    buffer_addr=(ulong)ram; buffer_size=16; upload_id=7; task_id=100;
    flash_all_alloc_addr=0; flash_all_alloc_size=0; flash_all_upload_ready=false;
    env_writes=allocations=releases=download_calls=0;
    gd->ram_base=(phys_addr_t)ram; gd->ram_size=sizeof(ram);
    gd->start_addr_sp=(phys_addr_t)(ram+sizeof(ram));
}
static int http_status(const char *uri,const char *body)
{
    struct fs_file f={0}; char text[20000]; int code=0;
    CHECK(fs_open_custom(&f,uri)==1);
    CHECK(f.len < sizeof(text));
    memcpy(text,f.data,f.len); text[f.len]=0;
    CHECK(sscanf(text,"HTTP/1.1 %d",&code)==1);
    if (body) CHECK(strstr(text,body)!=NULL);
    struct http_file *owner=f.pextension;
    if (owner->reply) replies--;
    free(owner->allocation); free(owner);
    return code;
}
static void task_request(const char *payload,int expected)
{
    char response[80]={0}; u8_t window=0; int connection;
    int old_task=task_id,old_writes=env_writes;
    CHECK(httpd_post_begin(&connection,"/api/task",NULL,0,strlen(payload),response,sizeof(response),&window)==ERR_OK);
    struct pbuf p={strlen(payload),payload};
    CHECK(httpd_post_receive_data(&connection,&p)==ERR_OK);
    httpd_post_finished(&connection,response,sizeof(response));
    CHECK(post_state.connection==NULL);
    CHECK(http_status(response,expected==403 ? "manual or physical recovery required" : NULL)==expected);
    if (expected!=200) {
        CHECK(task_id==old_task); CHECK(job_state==HTTP_JOB_IDLE);
        CHECK(env_writes==old_writes);
    } else {
        CHECK(task_id==old_task+1); CHECK(job_state==HTTP_JOB_QUEUED);
    }
}
int main(void)
{
    const char *blocked[]={"command","env-set","flash","flash-all","flash-bl2","flash-uboot","flash-board-data","ubi-rebuild","nand-scrub","backup","write","boot-upload","exit","new-operation"};
    for (size_t i=0;i<ARRAY_SIZE(blocked);i++) {
        setup(false); char payload[300];
        snprintf(payload,sizeof(payload),"{\"operation\":\"%s\"}",blocked[i]);
        task_request(payload,403); CHECK(job_kind==HTTP_JOB_NONE);
    }
    setup(false); task_request("{\"operation\":\"command\",\"upload_id\":\"invalid\",\"command\":\"httpd dhcp\"}",403);
    setup(false); task_request("{\"operation\":\"env-set\",\"name\":\"httpd_privileged\",\"value\":\"1\"}",403);
    setup(false); task_request("{\"operation\":\"\\u0063ommand\"}",403);
    setup(false); task_request("{\"operation\":\"reset\"}",200); CHECK(!strcmp(action_buf,"reset"));
    setup(false); task_request("{\"operation\":\"boot-production\"}",200); CHECK(!strcmp(action_buf,"boot-production"));
    setup(false); task_request("{\"operation\":\"\\u0072eset\"}",200);
    setup(false); task_request("{}",400);
    setup(false); task_request("{broken",400);
    setup(false); task_request("{\"operation\":\"reset\",\"upload_id\":\"invalid\"}",400);
    for (int busy=0;busy<2;busy++) for (int n=0;n<2;n++) {
        setup(false); job_state=busy?HTTP_JOB_RUNNING:HTTP_JOB_IDLE;
        char response[80]={0}; u8_t window=0; int connection;
        CHECK(httpd_post_begin(&connection,n?"/api/upload-all-flash":"/api/upload",NULL,0,16,response,sizeof(response),&window)==ERR_ARG);
        CHECK(http_status(response,"HTTP/1.1 403 Forbidden")==403);
        CHECK(!post_state.connection); CHECK(env_writes==0);
        CHECK(allocations==0); CHECK(releases==0);
    }
    setup(false); backup_ready=true;
    CHECK(http_status("/api/download/100/0/16",NULL)==403); CHECK(download_calls==0);
    setup(false); build_info();
    CHECK(http_status("/api/info","\"privileged\":false")==200);
    CHECK(http_status("/api/device","\"privileged\":false")==200);
    CHECK(http_status("/api/storage",NULL)==200);
    CHECK(http_status("/api/env",NULL)==200);
    CHECK(http_status("/api/task",NULL)==200);
    setup(true); build_info();
    CHECK(http_status("/api/info","\"privileged\":true")==200);
    CHECK(http_status("/api/device","\"privileged\":true")==200);
    struct fs_file unused={0};
    CHECK(fs_open_custom(&unused,"/api/download/100/0/16")==1); CHECK(download_calls==1);
    const char *full[]={
        "{\"operation\":\"command\",\"command\":\"version\"}",
        "{\"operation\":\"env-set\",\"name\":\"ipaddr\",\"value\":\"192.168.0.1\"}",
        "{\"operation\":\"flash\",\"upload_id\":7}",
        "{\"operation\":\"flash-bl2\",\"upload_id\":7}",
        "{\"operation\":\"flash-uboot\",\"upload_id\":7}",
        "{\"operation\":\"flash-board-data\",\"target\":\"factory\",\"upload_id\":7}",
        "{\"operation\":\"ubi-rebuild\"}","{\"operation\":\"nand-scrub\"}",
        "{\"operation\":\"backup\",\"kind\":\"mtd\",\"target\":\"ubi\"}",
        "{\"operation\":\"write\",\"kind\":\"mtd\",\"target\":\"ubi\",\"upload_id\":7}",
        "{\"operation\":\"boot-upload\",\"upload_id\":7}",
        "{\"operation\":\"exit\"}","{\"operation\":\"reset\"}","{\"operation\":\"boot-production\"}"
    };
    for (size_t i=0;i<ARRAY_SIZE(full);i++) { setup(true); task_request(full[i],200); }
    setup(true); flash_all_upload_ready=true;
    flash_all_alloc_addr=buffer_addr; flash_all_alloc_size=buffer_size;
    task_request("{\"operation\":\"flash-all\",\"upload_id\":7}",200);
    for (int n=0;n<2;n++) {
        setup(true); char response[80]={0}; u8_t window=0; int connection;
        CHECK(httpd_post_begin(&connection,n?"/api/upload-all-flash":"/api/upload",NULL,0,4,response,sizeof(response),&window)==ERR_OK);
        struct pbuf p={4,"data"}; CHECK(httpd_post_receive_data(&connection,&p)==ERR_OK);
        httpd_post_finished(&connection,response,sizeof(response));
        CHECK(http_status(response,NULL)==200); CHECK(buffer_size==4); CHECK(!memcmp(ram,"data",4));
        CHECK(flash_all_upload_ready==(bool)n);
    }
    char *plain[]={"httpd"},*dhcp[]={"httpd","dhcp"};
    char *safe[]={"httpd","safe"},*both[]={"httpd","dhcp","safe"};
    char *reverse[]={"httpd","safe","dhcp"},*bad[]={"httpd","bad"};
    char *duplicate[]={"httpd","safe","safe"},*dupdhcp[]={"httpd","dhcp","dhcp"};
    setup(false); CHECK(do_httpd(NULL,0,1,plain)==0); CHECK(httpd_privileged);
    setup(false); CHECK(do_httpd(NULL,0,2,dhcp)==0); CHECK(httpd_privileged);
    setup(true); CHECK(do_httpd(NULL,0,2,safe)==0); CHECK(!httpd_privileged);
    setup(true); CHECK(do_httpd(NULL,0,3,both)==0); CHECK(!httpd_privileged);
    setup(true); CHECK(do_httpd(NULL,0,3,reverse)==0); CHECK(!httpd_privileged);
    setup(false); CHECK(do_httpd(NULL,0,2,bad)==CMD_RET_USAGE);
    CHECK(do_httpd(NULL,0,3,duplicate)==CMD_RET_USAGE);
    CHECK(do_httpd(NULL,0,3,dupdhcp)==CMD_RET_USAGE);
    CHECK(do_httpd(NULL,0,4,duplicate)==CMD_RET_USAGE);
    setup(false); httpd_running=true;
    CHECK(uboot_httpd_start(true)==0); CHECK(!httpd_privileged);
    CHECK(do_httpd(NULL,0,2,dhcp)==0); CHECK(!httpd_privileged);
    httpd_running=false; CHECK(uboot_httpd_start(true)==0); CHECK(httpd_privileged);
    CHECK(strstr(info_buf,"\"privileged\":true"));
    CHECK(uboot_httpd_start_mode(true,false)==0); CHECK(!httpd_privileged);
    CHECK(strstr(info_buf,"\"privileged\":false"));
    network_fail=-EIO; CHECK(do_httpd(NULL,0,3,both)==CMD_RET_FAILURE);
    CHECK(!httpd_running); network_fail=0;
    CHECK(uboot_httpd_start(true)==0); CHECK(httpd_privileged);
    printf("PASS: %d compiled C assertions (actual HTTP callbacks, parser, startup and command; hardware stubbed).\n",checks);
    return 0;
}
