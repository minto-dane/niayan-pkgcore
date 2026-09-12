/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

static const char *mode_path;
static void mode(char value[64]) {
    FILE *file=fopen(mode_path,"r");if(!file)exit(2);
    if(!fgets(value,64,file))exit(2);
    fclose(file);value[strcspn(value,"\r\n")]=0;
}
static int authorize(sd_bus_message *m,void *userdata,sd_bus_error *error) {
    (void)userdata;(void)error;
    const char *kind,*key,*action,*plan,*request,*cancel;int fd=-1,uid=-1;uint32_t flags=0;
    if(sd_bus_message_enter_container(m,'r',"sa{sv}")<=0 || sd_bus_message_read(m,"s",&kind)<=0 || strcmp(kind,"unix-process") ||
       sd_bus_message_enter_container(m,'a',"{sv}")<=0 || sd_bus_message_read(m,"{sv}",&key,"h",&fd)<=0 || strcmp(key,"pidfd") ||
       sd_bus_message_read(m,"{sv}",&key,"i",&uid)<=0 || strcmp(key,"uid") || uid!=65534 ||
       !sd_bus_message_at_end(m,0) || sd_bus_message_exit_container(m)<0 || sd_bus_message_exit_container(m)<0 ||
       sd_bus_message_read(m,"s",&action)<=0 || strcmp(action,"org.niaos.package.manage") ||
       sd_bus_message_enter_container(m,'a',"{ss}")<=0 || sd_bus_message_read(m,"{ss}",&key,&plan)<=0 || strcmp(key,"nia.plan") || strlen(plan)!=64 ||
       sd_bus_message_read(m,"{ss}",&key,&request)<=0 || strcmp(key,"nia.request") || strlen(request)!=32 ||
       !sd_bus_message_at_end(m,0) || sd_bus_message_exit_container(m)<0 || sd_bus_message_read(m,"us",&flags,&cancel)<=0 ||
       flags>1 || strcmp(cancel,request) || !sd_bus_message_at_end(m,1)) return sd_bus_reply_method_errorf(m,"org.niaos.Fixture.Invalid","invalid client frame");
    struct pollfd p={.fd=fd,.events=POLLIN};if(poll(&p,1,0)!=0)return -1;
    char selected[64];mode(selected);
    if(!strcmp(selected,"silent"))return 1;
    if(!strcmp(selected,"bad-signature"))return sd_bus_reply_method_return(m,"s","invalid");
    if(!strcmp(selected,"changed"))sd_bus_emit_signal(sd_bus_message_get_bus(m),"/org/freedesktop/PolicyKit1/Authority","org.freedesktop.PolicyKit1.Authority","Changed","");
    sd_bus_message *reply=NULL;int result=-1;
    if(sd_bus_message_new_method_return(m,&reply)<0 || sd_bus_message_open_container(reply,'r',"bba{ss}")<0 ||
       sd_bus_message_append(reply,"bb",strcmp(selected,"deny")!=0,!strcmp(selected,"challenge"))<0 ||
       sd_bus_message_open_container(reply,'a',"{ss}")<0)goto out;
    if(!strcmp(selected,"retained")) {
        if(sd_bus_message_append(reply,"{ss}","polkit.temporary_authorization_id","temporary")<0)goto out;
    } else if(!strcmp(selected,"large-detail")) {
        char value[1100];memset(value,'x',sizeof(value)-1);value[sizeof(value)-1]=0;
        if(sd_bus_message_append(reply,"{ss}","detail",value)<0)goto out;
    } else if(!strcmp(selected,"many-details")) {
        for(unsigned i=0;i<17;++i) {char name[32];snprintf(name,sizeof(name),"detail-%u",i);if(sd_bus_message_append(reply,"{ss}",name,"x")<0)goto out;}
    }
    if(sd_bus_message_close_container(reply)<0 || sd_bus_message_close_container(reply)<0)goto out;
    result=sd_bus_send(NULL,reply,NULL);
out:
    sd_bus_message_unref(reply);return result<0?result:1;
}
static const sd_bus_vtable methods[]={
    SD_BUS_VTABLE_START(0),
    SD_BUS_METHOD("CheckAuthorization","(sa{sv})sa{ss}us","(bba{ss})",authorize,SD_BUS_VTABLE_UNPRIVILEGED),
    SD_BUS_SIGNAL("Changed","",0),SD_BUS_VTABLE_END
};
int main(int argc,char **argv) {
    if(argc!=2 || getuid())return 2;
    mode_path=argv[1];
    sd_bus *bus=NULL;sd_bus_slot *slot=NULL;
    if(sd_bus_new(&bus)<0 || sd_bus_set_address(bus,"unix:path=/run/dbus/system_bus_socket")<0 ||
       sd_bus_set_bus_client(bus,1)<0 || sd_bus_negotiate_fds(bus,1)<0 || sd_bus_start(bus)<0 ||
       sd_bus_add_object_vtable(bus,&slot,"/org/freedesktop/PolicyKit1/Authority","org.freedesktop.PolicyKit1.Authority",methods,NULL)<0 ||
       sd_bus_request_name(bus,"org.freedesktop.PolicyKit1",0)<0)return 2;
    puts("ready");fflush(stdout);
    for(;;) {int n=sd_bus_process(bus,NULL);if(n<0)return 2;if(!n && sd_bus_wait(bus,100000)<0)return 2;}
}
