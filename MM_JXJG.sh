#!/bin/sh - 
#===============================================================================
#
#          FILE: MM_JXJG.sh
# 
#         USAGE: ./MM_JXJG.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: lianghuiqiang (leung4080@gmail.com), 
#  ORGANIZATION: 
#       CREATED: 2015/8/24 13:04:33 中国标准时间
#      REVISION:  ---
#===============================================================================

export LANG=C
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin:/usr/local/sbin
THIS_PID=$$
DATE=`date +%Y%m%d`
#进入脚本所在目录
SCRIPT_PATH=$(dirname $0);
cd $SCRIPT_PATH;

mkdir -p /tmp/JXJG
BackupFileList=/tmp/JXJG/backupfile_"$DATE".list
CHMOD_BackupList=/tmp/JXJG/Chmod_backup_"$DATE".list
Other_BackupList=/tmp/JXJG/Other_backup_"$DATE".list
Restore_script=/tmp/JXJG/run_restore.sh


#===============================================================================
#  FUNCTION DEFINITIONS
#===============================================================================

RUN_LINUX() 
{
  #echo -n linux
  linux_sub_UMASK;    
  linux_sub_CHMOD;
  linux_sub_SYSCTL;
  linux_sub_syslogng;
  linux_sub_syslog;
  linux_sub_rsyslog;
  linux_sub_setTMOUT;
  linux_sub_pam;
  linux_sub_logindefs;
  linux_sub_sshdconfig;
  linux_sub_limit;
  linux_sub_findsuid;
  linux_sub_distelnet;
  linux_sub_disxinetd;
  linux_sub_profile;
  linux_sub_userlock;
  linux_sub_aliases;
  linux_sub_services;
  linux_sub_vsftpd;
  linux_sub_snmp;
  linux_sub_issue;
  linux_sub_findrhost;
  linux_sub_logfile_chmod;

  create_Restore_file;

 # Restore_file;
  
}
RUN_HPUX() 
{
   echo HPUX
}

linux_sub_UMASK(){
  #在文件/etc/csh.cshrc中设置 umask 027或UMASK 027
  Filename="/etc/csh.cshrc"
  setUMASK $Filename "027" on 

  #检查文件/etc/bashrc（或/etc/bash.bashrc）中设置 umask 027或UMASK 027
  Filename="/etc/bashrc"
  setUMASK $Filename "027" on;

  ##在文件/etc/csh.login中设置 umask 027或UMASK 027
  Filename="/etc/csh.login"
  setUMASK $Filename "027" on ;
  
  ##在文件/etc/profile中设置umask 027或UMASK 027
  Filename="/etc/profile"
  setUMASK $Filename "027" on ;

  #设置默认权限：vi /etc/login.defs，
  #在末尾增加umask 027或UMASK  027，将缺省访问权限设置为750。
  setUMASK "/etc/login.defs" "027" on;
}

linux_sub_CHMOD(){
  #chmod 750 /etc/inetd.conf
  #
  chmodFile "/etc/inetd.conf" "750" on;

  #chmod 750 /tmp
  chmodFile "/tmp" "1750" ;

  #chmod 750 /etc/shadow
  chmodFile "/etc/shadow" "750" ;

  # chmod 750 /etc/rc2.d/
  chmodFile "/etc/rc2.d/" "750" on

  #chmod 700 /etc/ssh/ssh_host_dsa_key
  chmodFile "/etc/ssh/ssh_host_dsa_key" "700" ;

  #chmod 750 /etc/rc5.d/
  chmodFile "/etc/rc5.d/" "750" on;

  #chmod 755 /etc/group
  chmodFile "/etc/group" "755" ;

  #chmod 750 /etc/rc1.d/
  chmodFile "/etc/rc1.d/" "750" on;

  #chmod 750 /etc/rc6.d/
  chmodFile "/etc/rc6.d/" "750" on;

  #chmod 750 /etc/services
  chmodFile "/etc/services" "750" ;

  #chmod 750 /etc/rc.d/init.d/
  chmodFile "/etc/rc.d/init.d/" "750" on;

  #chmod 750 /etc/rc3.d/
  chmodFile "/etc/rc3.d/" "750" on;

  #chmod 750 /etc/rc4.d/
  chmodFile "/etc/rc4.d/" "750" on;

  #chmod 750 /etc/rc0.d/
  chmodFile "/etc/rc4.d/" "750" on;

  #chmod 755 /etc/passwd
  chmodFile "/etc/passwd" "755" ;

  #chmod 700 /etc/ssh/ssh_host_rsa_key
  chmodFile "/etc/ssh/ssh_host_rsa_key" "700" ;

  #chmod 750 /etc/
  chmodFile "/etc/" "755" ;

  #如果/etc/grub.conf文件存在，且非链接文件，则执行chmod 600 /etc/grub.conf;
  #如果/boot/grub/grub.conf文件存在，则执行chmod 600 /boot/grub/grub.conf;
  #如果/etc/lilo.conf文件存在，则执行chmod 600 /etc/lilo.conf。

  chmodFile "/etc/grub.conf" "600" 
  chmodFile "/boot/grub/grub.conf" "600" on
  chmodFile "/etc/lilo.conf" "600" on

  #chmod 600 /etc/xinetd.conf
  chmodFile "/etc/xinetd.conf" "600" on

  #chmod 600 /etc/security
  chmodFile "/etc/security" "600" 


}
linux_sub_syslogng(){
#在/etc/syslog-ng/syslog-ng.conf中配置destination logserver { udp("10.10.10.10" port(514)); };
#log { source(src); destination(logserver); };
#可以将此处10.10.10.10替换为实际的IP
  Log_server="10.101.1.61"
  Filename="/etc/syslog-ng/syslog-ng.conf"
  sub_switch="on"

  tmp=`grep "destination logserver" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #"
    else
      if [ $sub_switch = "on" ] ; then
          Backup_file $Filename
          mkdir `dirname $Filename`
          touch $Filename;
          echo "destination logserver { udp("$Log_server" port(514)); };" >> $Filename
          echo "log { source(src); destination(logserver); };" >> $Filename
          echo "[Fix]$Filename#"   
      else
            echo "[Not] $Filename #"
      fi
    fi
}

linux_sub_syslogng2(){
#编辑/etc/syslog-ng/syslog-ng.conf
#配置：
#filter f_msgs { level(err) or facility(kern) and level(debug) or facility(daemon) and level(notice); };
#destination msgs { file("/var/adm/msgs"); };
#log { source(src); filter(f_msgs); destination(msgs); };
#其中/var/adm/msgs为日志文件。
#如果该文件不存在，则创建该文件，命令为：
#touch /var/adm/msgs，并修改权限为666.命令为：chmod 666 /var/adm/msgs.   
#重启日志服务：
#/etc/init.d/syslog restart

  Filename="/etc/syslog-ng/syslog-ng.conf"
  sub_switch="on"

  tmp=`grep "/var/adm/msgs" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #"
    else
      if [ $sub_switch = "on" ] ; then
          Backup_file $Filename
          FILE_DIR=`dirname $Filename`;
          if [ ! -d "$FILE_DIR" ] ; then
             mkdir -p $FILE_DIR 
          fi
          if [ ! -e "$Filename" ] ; then 
            touch $Filename;
          fi
          echo "filter f_msgs { level(err) or facility(kern) and level(debug) or facility(daemon) and level(notice); };" >> $Filename
          echo "destination msgs { file("/var/adm/msgs"); };" >> $Filename
          echo "log { source(src); filter(f_msgs); destination(msgs); };" >> $Filename

          LOGFILE="/var/adm/msgs"
          FILE_DIR2=`dirname $LOGFILE`;
          if [ ! -d "$FILE_DIR2" ] ; then
             mkdir -p $FILE_DIR2 
          fi
          if [ ! -e "$LOGFILE" ] ; then 
            touch $LOGFILE;
          fi

          chmodFile "$LOGFILE" "666" on  >/dev/null 2>&1 

          echo "[Fix]$Filename#"   
      else
            echo "[Not] $Filename #"
      fi
    fi


  
}

linux_sub_syslog(){
#修改配置文件vi /etc/syslog.conf，
#加上这一行：
#*.*                    @192.168.0.1
#可以将"*.*"替换为你实际需要的日志信息。比如：kern.* ; mail.* 等等。
#可以将此处192.168.0.1替换为实际的IP或域名(域名格式形如：www.nsfocus.com,根据具体情况填写)。
  Log_server="10.101.1.61"
  Filename="/etc/syslog.conf"
  sub_switch="on"

  tmp=`grep "@$Log_server" $Filename 2>/dev/null`
  if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #"
  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      echo "*.*                    @"$Log_server >> $Filename;
      echo "[Fix]$Filename#"
    else
      echo "[Not] $Filename #"
    fi
  fi
}
linux_sub_rsyslog(){
#修改配置文件vi /etc/rsyslog.conf，
#加上这一行：
#*.*                    @192.168.0.1
#可以将"*.*"替换为你实际需要的日志信息。比如：kern.* ; mail.* 等等。
#可以将此处192.168.0.1替换为实际的IP或域名(域名格式形如：www.nsfocus.com,根据具体情况填写)。
  Log_server="10.101.1.61"
  Filename="/etc/rsyslog.conf"
  sub_switch="on"

  tmp=`grep "@$Log_server" $Filename 2>/dev/null`
  if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #"
  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      echo "*.*                    @"$Log_server >> $Filename;
      echo "[Fix]$Filename#"
    else
     echo "[Not] $Filename #"
    fi
  fi
}
linux_sub_setTMOUT(){
#以root账户执行，vi /etc/profile,增加 export TMOUT=180(单位：秒，可根据具体情况设定超时退出时间，要求不小于180秒),注销用户，再用该用户登录激活该功能
  Filename="/etc/profile"
  sub_switch="on"

  tmp=`grep "TMOUT=180" $Filename 2>/dev/null`
  if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #"
  else
  
    if [ $sub_switch = "on" ] ; then
      Backup_file $Filename
      echo "export TMOUT=180" >> $Filename;
      echo "export TMOUT=600" >> $Filename;
      echo "[Fix]$Filename#"
    else
      echo "[Not] $Filename #"
    fi
  fi

}

linux_sub_pam(){
#Redhat:编辑/etc/pam.d/system-auth文件，
#修改设置如下
#auth  required  pam_tally.so deny=10 unlock_time=300 no_lock_time
#account  required   pam_tally.so
#参数说明：
#deny        #连续认证失败次数超过的次数
#unlock_time  #锁定的时间，单位为秒
  Filename="/etc/pam.d/system-auth"
  sub_switch="on"
 
  tmp=`grep "unlock_time=300" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #"
    else
  if [ $sub_switch = "on" ] ; then
      Backup_file $Filename
    echo "#auth  required  pam_tally.so deny=10 unlock_time=300 no_lock_time" >> $Filename;
    echo "#account  required   pam_tally.so">> $Filename;
    echo "password  requisite pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1" >> $Filename
    echo "[Fix]$Filename#"
  else
   
      echo "[Not] $Filename #"
    fi
  fi

  #Redhat系统：修改/etc/pam.d/system-auth文件,
#在ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 选3种，追加到password  requisite pam_cracklib.so后面，添加到配置文件中。
#例如：password  requisite pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1
#注：ucredit：大写字母个数；lcredit：小写字母个数；dcredit：数字个数；ocredit：特殊字符个数

  Filename="/etc/pam.d/system-auth"
  sub_switch="on"
 
  tmp=`egrep "pam_cracklib.so.*credit" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #"
    else
  if [ "$sub_switch" = "on" ] ; then
      Backup_file $Filename
    echo "password  requisite pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1" >> $Filename;
      echo "[Fix]$Filename#";
  else
   
      echo "[Not] $Filename #"
    fi
  fi

    
  #编辑 /etc/pam.d/login文件，配置auth required pam_securetty.so
  Filename="/etc/pam.d/login"
  sub_switch="on"

 tmp=`grep "pam_securetty.so" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #"
    else
    if [ $sub_switch = "on" ] ; then
      Backup_file $Filename
    echo "#auth required pam_securetty.so" >> $Filename;
    echo "[Fix]$Filename#"
  else
   
      echo "[Not] $Filename #"
    fi
  fi
##Redhat:编辑/etc/pam.d/system-auth文件，
##修改设置如下
##password sufficient pam_unix.so md5 shadow nullok try_first_pass use_authtok remember=5 
##补充操作说明
##只需在password sufficient这一行加上remember=5即可
##NIS系统无法生效，非NIS系统或NIS+系统能够生效。

  Filename="/etc/pam.d/system-auth"
  sub_switch="on"
 
  tmp=`egrep "^password.*sufficient.*remember.*" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #"
    else
  if [ "$sub_switch" = "on" ] ; then
      Backup_file $Filename
      sed -i 's/^password.*sufficient.*/&\ remember=5/' $Filename;
      echo "[Fix]$Filename#";
  else
   
      echo "[Not] $Filename #"
    fi
  fi



}


linux_sub_logindefs(){
#在文件/etc/login.defs中设置 PASS_MIN_LEN 不小于标准值
  Filename="/etc/login.defs"
  sub_switch="on"
  
  PML=`egrep '^PASS_MIN_LEN' $Filename|awk '{print $NF}' 2>/dev/null`
  if [ "$PML" -ge  "12" ]  ; then
    echo "[OK]$Filename PASS_MIN_LEN $PML#"
  else 

  if [ $sub_switch = "on" ] ; then
      Backup_file $Filename
     if [ -z "$PML"  ]  ; then
        echo "PASS_MIN_LEN   12" >> $Filename;
      else
        sed -i 's/^\(PASS_MIN_LEN\).*/#&\n\1\t12/' $Filename;
      fi
      echo "[Fix]$Filename PASS_MIN_LEN";
  else
      echo "[Not]$Filename PASS_MIN_LEN $PML" 
  fi
  fi


  Filename="/etc/login.defs"
  sub_switch="on"
  
  PML=`egrep '^PASS_MIN_DAYS' $Filename|awk '{print $NF}' 2>/dev/null`
  if [ "$PML" -ge  "7" ]  ; then
    echo "[OK]$Filename PASS_MIN_DAYS $PML#"
    return 0;
  fi

  if [ $sub_switch = "on" ] ; then
      Backup_file $Filename
     if [ -z "$PML"  ]  ; then
        echo "PASS_MIN_DAYS   7" >> $Filename;
      else
        sed -i 's/^\(PASS_MIN_DAYS\).*/#&\n\1\t7/' $Filename;
      fi
      echo "[Fix]$Filename PASS_MIN_DAYS";
  else
      echo "[Not]$Filename PASS_MIN_DAYS $PML" 
  fi



}


linux_sub_sshdconfig(){

#修改/etc/ssh/sshd_config文件,配置PermitRootLogin no。

  Filename="/etc/ssh/sshd_config"
  sub_switch="on"

   PRL=`awk '$1~/^PermitRootLogin/{print $2}' $Filename|tail -1`;
  if [ "$PRL" = "no" ] ; then
    echo "[OK]$Filename PermitRootLogin $PRL#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      if [ -z "$PRL" ] ; then
        echo "PermitRootLogin no"  >> $Filename;
      else
        sed -i 's/^\(PermitRootLogin\).*/#&\n\1\tno/' $Filename;
      fi
      echo "[Fix]$Filename PermitRootLogin";
    else
      echo "[Not]$Filename PermitRootLogin $PML" 
    fi
  fi

#Protocol 2
  Filename="/etc/ssh/sshd_config"
  sub_switch="on"

   PRL=`awk '$1~/^Protocol/{print $2}' $Filename|tail -1 `;
  if [ "$PRL" = "2" ] ; then
    echo "[OK]$Filename Protocol $PRL#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      if [ -z "$PRL" ] ; then
        echo "Protocol  2"  >> $Filename;
      else
        sed -i 's/^\(Protocol\).*/#&\n\1\t2/' $Filename;
      fi
      echo "[Fix]$Filename Protocol";
    else
      echo "[Not]$Filename Protocol $PML" 
    fi
  fi


#1. 执行如下命令创建ssh banner信息文件：
##touch /etc/ssh_banner
##chown bin:bin /etc/ssh_banner
##chmod 644 /etc/ssh_banner
##echo "" Authorized only. All activity will be monitored and reported "" > /etc/ssh_banner
#可根据实际需要修改该文件的内容。
#2. 修改/etc/ssh/sshd_config文件，添加如下行：
#Banner /etc/ssh_banner
#3.重启sshd服务：
##/etc/init.d/sshd restart 
  Filename="/etc/ssh/sshd_config"
  Filename2="/etc/ssh_banner"
  sub_switch="on"

   PRL=`awk '$1~/^Banner/{print $2}' $Filename|tail -1 `;
   if [ -e "$Filename2" ] ; then
      tmp=`grep "Authorized only." $Filename2 2>/dev/null`;
   fi
  if [ "$PRL" = "/etc/ssh_banner" ] && [ -n "$tmp" ] ; then
    echo "[OK]$Filename Banner $PRL#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename

      if [ ! -e $Filename2 ] ; then
        touch $Filename2;
        chown bin:bin $Filename2;
        chmod 644 $Filename2;
        echo " Authorized only. All activity will be monitored and reported " > $Filename2;
      fi


      if [ -z "$PRL" ] ; then
        echo "Banner /etc/ssh_banner"  >> $Filename;
      else
        sed -i 's/^\(Banner\).*/#&\n\1\t\/etc\/ssh_banner/' $Filename;
      fi
      echo "[Fix]$Filename Banner";
    else
      echo "[Not]$Filename Banner $PML" 
    fi
  fi


}

linux_sub_limit(){
#在文件/etc/security/limits.conf中配置* soft core 0
  Filename="/etc/security/limits.conf"
  sub_switch="on"

   PRL=`awk '$0~/^*.*soft.*core/' $Filename|wc -l`;
  if [ $PRL -gt 0 ] ; then
    echo "[OK]$Filename soft core#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename

      echo  "* soft core 0" >> $Filename;
      echo "[Fix]$Filename soft core";
    else
      echo "[Not]$Filename soft core " 
    fi
  fi


#在文件/etc/security/limits.conf中配置* hard core 0
  Filename="/etc/security/limits.conf"
  sub_switch="on"

   PRL=`awk '$0~/^*.*hard.*core/' $Filename|wc -l`;
  if [ $PRL -gt 0 ] ; then
    echo "[OK]$Filename hard core#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename

      echo  "* hard core 0" >> $Filename;
      echo "[Fix]$Filename hard core";
    else
      echo "[Not]$Filename hard core " 
    fi
  fi


}
linux_sub_findsuid(){
#执行命令:
#find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport -type f -perm +6000 2>/dev/null
#如果存在输出结果，则使用chmod 755 文件名 命令修改文件的权限。
#例如：chmod a-s /usr/bin/chage
 # Results=`LANG=C find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport -type f -perm +6000 2>/dev/null`
  Results=`LANG=C find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /sbin/netreport -type f -perm +6000 2>/dev/null`
  sub_switch="on"
  
  if [ -n "$Results" ] ; then
    
    if [ "$sub_switch" = "on" ] ; then
      echo -n "[Fix]chmod-suid :"
      for i in "$Results" ; do
        chmod a-s $i
        echo -n "$i";
      done
       printf "#\n"
    else
      echo "[Not]chmod-suid #"
    fi

  else
    echo "[OK]chmod-suid #"
  fi

}

linux_sub_distelnet(){

#在/etc/services文件中，注释掉 telnet        23/tcp 一行(如不生效重启telnetd服务或xinetd服务或系统，例如，Red Hat 上重启xinetd：service xinetd restart，根据实际情况操作)
  
  Filename="/etc/services"
  sub_switch="on"

   tmp=`egrep "^telnet.*23\/tcp" $Filename 2>/dev/null`
  if [ -z "$tmp" ] ; then
      echo "[OK] $Filename #"
  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
       sed -i 's/^telnet.*23.*tcp/#&/g' $Filename;
      echo "[Fix]$Filename#"
    else
       echo "[Not] $Filename #"
    fi

  fi


}

linux_sub_disxinetd(){
#查看所有开启的服务：
##ps aux 
#禁用inetd.d 目录中不用的服务：
##vi /etc/inid.d/servicename 
#将服务文件里面的disable设置为disable=yes重启xinetd服务,即可。
#要直接关闭某个服务，如sshd可用如下命令:
## /etc/init.d/sshd stop #关闭正在运行的sshd服务
#补充操作说明
#关闭下列不必要的基本网络服务。
#chargen-dgram daytime-stream echo-streamklogin  tcpmux-server chargen-stream  discard-dgram   eklogin  krb5-telnet  tftp cvs  discard-stream  ekrb5-telnet  kshell  time-dgram daytime-dgram   echo-dgram gssftp  rsync  time-stream
    sub_switch="on"
     if [ $sub_switch = "on" ] ; then
      ARGS="chargen-dgram daytime-stream echo-streamklogin  tcpmux-server chargen-stream  discard-dgram   eklogin  krb5-telnet  tftp cvs  discard-stream  ekrb5-telnet  kshell  time-dgram daytime-dgram   echo-dgram gssftp  rsync  time-stream sendmail ldp discard discard-udp bootps ypbind time time-udp" 
       for i in $ARGS ; do
       
       chkconfig $i off  2>/dev/null
       
       
       done
     fi


}

linux_sub_SYSCTL(){
#1.备份配置文件
#cp -p /proc/sys/net/ipv4/conf/all/accept_redirects  /proc/sys/net/ipv4/conf/all/accept_redirects.bak
#2.执行命令
#sysctl -w net.ipv4.conf.all.accept_redirects=""0""
#并修改/proc/sys/net/ipv4/conf/all/accept_redirects的值为0"
#"1.备份配置文件
#cp -p /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts  /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts.bak
#2.执行命令
#sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=""1""
#并修改/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts的值为1"
#"1.备份配置文件
#cp -p /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/ip_forward.bak
#2.执行命令
#sysctl -w net.ipv4.ip_forward=""0""
#并修改/proc/sys/net/ipv4/ip_forward的值为0"
#cp -p /proc/sys/net/ipv4/conf/all/accept_redirects  /proc/sys/net/ipv4/conf/all/accept_redirects.bak
#cp -p /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts  /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts.bak
#cp -p /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/ip_forward.bak
#sysctl -w net.ipv4.conf.all.accept_redirects=""0""
#sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=""1""
#sysctl -w net.ipv4.ip_forward=""0""
setSysctl "net.ipv4.conf.all.accept_redirects" "0" on
setSysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1" on
setSysctl "net.ipv4.ip_forward" "0" on



}

linux_sub_profile(){
#编辑文件/etc/profile，将HISTSIZE 值修改为5
  Filename="/etc/profile"
  sub_switch="on"

   PRL=`awk -F"=" '$1~/^HISTSIZE/{print $2}' $Filename|tail -1`;
  if [ "$PRL" = "5" ] ; then
    echo "[OK]$Filename HISTSIZE $PRL#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      if [ -z "$PRL" ] ; then
        echo "HISTSIZE=5"  >> $Filename;
      else
        sed -i 's/^\(HISTSIZE\).*/#&\n\1=5/' $Filename;
      fi
      echo "[Fix]$Filename HISTSIZE";
    else
      echo "[Not]$Filename HISTSIZE $PML" 
    fi
  fi
}

linux_sub_userlock(){
#删除用户:#userdel username; 
#锁定用户：
#usermod -L username
#只有具备超级用户权限的使用者方可使用.
#usermod –U username可以解锁。
#补充操作说明
#需要锁定的用户：adm,lp,mail,uucp,operator,games,gopher,ftp,nobody,nobody4,noaccess,listen,webservd,rpm,dbus,avahi,mailnull,smmsp,nscd,vcsa,rpc,rpcuser,nfs,sshd,pcap,ntp,haldaemon,distcache,apache,webalizer,squid,xfs,gdm,sabayon,named。
  UserList="adm lp mail uucp operator games gopher ftp nobody nobody4 noaccess listen webservd rpm dbus avahi mailnull smmsp nscd vcsa rpc rpcuser nfs sshd pcap ntp haldaemon distcache apache webalizer squid xfs gdm sabayon named"
  sub_switch="on"
  
  tmp="";
  sys_userlist="";
  unlockusers="";
  
  for i in $UserList
  do
    tmp=`egrep "^$i:" /etc/shadow |awk -F":" '{print $1}'`
    if [ -n "$tmp" ] ; then
      sys_userlist="$sys_userlist $tmp"
    fi
  done

  if [ -z "$sys_userlist" ] ; then
      echo "[OK]lockusers #"
      return 0;
  fi

  for i in $sys_userlist
  do
    tmp=`egrep "^$i:" /etc/shadow |awk -F":" '$2!~/^!.*/{print $1}'`
    if [ -n "$tmp" ] ; then
      unlockusers="$unlockusers $tmp"  
    fi
  done
   
  if [ -z "$unlockusers" ] ; then
      echo "[OK]lockusers #"
      return 0;
  else
    
    if [ "$sub_switch" = "on" ] ; then
      echo -n "[Fix]usermod -L "
      for i in $unlockusers
      do
        echo -n "$i "
        usermod -L $i;
        echo "usermod -U $i" >> $Other_BackupList 2>/dev/null;
      done
      echo -n "#"
      printf "\n";
      
    else
      echo "[Not]unlock: $unlockusers#";
    fi

  fi

}

linux_sub_aliases(){
#参考配置操作
#编辑别名文件vi /etc/aliases，删除或注释掉下面的行
##games: root  
##ingres: root   
##system: root  
##toor: root    
##uucp: root    
##manager: root 
##dumper: root    
##operator: root   
##decode: root    
##root: marc
#补充操作说明
#更新后运行/usr/bin/newaliases，使改变生效

  Filename="/etc/aliases"
  sub_switch="on"

   PRL=`egrep "^games:.*root|^ingres:.*root|^system:.*root|^toor:.*root|^uucp:.*root|^manager:.*root|^dumper:.*root|^operator:.*root|^decode:.*root|^root:.*marc" $Filename|tail -1`;
  if [ -z "$PRL" ] ; then
    echo "[OK]$Filename#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      sed -i 's/^games:.*root/#&/g'    $Filename
      sed -i 's/^ingres:.*root/#&/g'   $Filename
      sed -i 's/^system:.*root/#&/g'   $Filename
      sed -i 's/^toor:.*root/#&/g'     $Filename
      sed -i 's/^uucp:.*root/#&/g'     $Filename
      sed -i 's/^manager:.*root/#&/g'  $Filename
      sed -i 's/^dumper:.*root/#&/g'   $Filename
      sed -i 's/^operator:.*root/#&/g' $Filename
      sed -i 's/^decode:.*root/#&/g'   $Filename
      sed -i 's/^root:.*marc/#&/g'     $Filename

      echo "[Fix]$Filename #";
    else
      echo "[Not]$Filename#" 
    fi
  fi
}

linux_sub_services(){
  #在/etc/services文件中，注释掉 telnet        23/tcp 一行(如不生效重启telnetd服务或xinetd服务或系统，例如，Red Hat 上重启xinetd：service xinetd restart，根据实际情况操作)
  Filename="/etc/services"
  sub_switch="on"

  tmp=`egrep '^telnet.*23.tcp' $Filename 2>/dev/null`
  if [ -z "$tmp" ] ; then
      echo "[OK] $Filename #"
  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      sed -i 's/^telnet.*23.tcp.*/#&/' $Filename
      echo "[Fix]$Filename#"
    else
     echo "[Not] $Filename #"
    fi
  fi
}

linux_sub_vsftpd(){
#/etc/vsftpd.conf(或/etc/vsftpd/vsftpd.conf)文件，设置：anonymous_enable=NO
 Filename="/etc/vsftpd/vsftpd.conf"
 Filename2="/etc/vsftpd.conf"
  sub_switch="on"

  tmp=`awk -F"=" '$1~/^anonymous_enable/{print $2}' $Filename 2>/dev/null`
  if [ "$tmp" = "NO" ] ; then
      echo "[OK] $Filename #"
  else
    if [ $sub_switch = "on" ] ; then
      if [ ! -e $Filename ] ; then
        mkdir -p /etc/vsftpd/
        touch /etc/vsftpd/vsftpd.conf
      fi
        Backup_file $Filename 

       if [ -z "$tmp" ] ; then
         echo "anonymous_enable=NO" >>$Filename
       fi
       sed -i 's/^\(anonymous_enable\).*/#&\n\1=NO/g' $Filename;
       if [ ! -e  "$Filename2" ] ; then
          ln -s $Filename $Filename2;
       fi
       echo "[Fix]$Filename anonymous_enable=NO#"
    else
     echo "[Not] $Filename #"
    fi
  fi
#在/etc/ftpusers文件中加入下列行
#root
  Filename="/etc/ftpusers"
  sub_switch="on"

  PRL=`egrep '^root.*' $Filename 2>/dev/null |tail -1`;
  if [ -n "$PRL" ] ; then
    echo "[OK]$Filename root#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      if [ -z "$PRL" ] ; then
        echo "root"  >> $Filename;
      fi
      echo "[Fix]$Filename root";
    else
      echo "[Not]$Filename root" 
    fi
  fi

##"如果系统使用vsftp：
##修改/etc/vsftpd.conf（或者为/etc/vsftpd/vsftpd.conf）
### vi /etc/vsftpd.conf
##确保以下行未被注释掉，如果没有该行，请添加：
##write_enable=YES //允许上传。如果不需要上传权限，此项可不进行更改。
##ls_recurse_enable=YES
##local_umask=022 //设置用户上传文件的属性为755
##anon_umask=022 //匿名用户上传文件(包括目录)的 umask
##重启网络服务
### /etc/init.d/vsftpd restart

##"1.vsftp
##修改/etc/vsftpd.conf(或者/etc/vsfptd/vsftpd.conf)
###vi /etc/vsftpd.conf
##确保以下行未被注释掉，如果没有该行，请添加：
##chroot_local_user=YES
##重启网络服务
###/etc/init.d/vsftpd restart
##

##1.修改vsftp回显信息
### vi /etc/vsftpd.conf(或/etc/vsftpd/vsftpd.conf)
##ftpd_banner=” Authorized users only. All activity will be monitored and reported.”
##可根据实际需要修改该文件内容。
##重启服务：
### /etc/init.d/vsftpd restart

 Filename="/etc/vsftpd/vsftpd.conf"
 Filename2="/etc/vsftpd.conf"
 sub_switch="on"

  tmp1=`awk -F"=" '$1~/^write_enable/{print $2}' $Filename 2>/dev/null`
  tmp2=`awk -F"=" '$1~/^ls_recurse_enable/{print $2}' $Filename 2>/dev/null`
  tmp3=`awk -F"=" '$1~/^local_umask/{print $2}' $Filename 2>/dev/null`
  tmp4=`awk -F"=" '$1~/^anon_umask/{print $2}' $Filename 2>/dev/null`
  tmp5=`awk -F"=" '$1~/^chroot_local_user/{print $2}' $Filename 2>/dev/null`
  tmp6=`awk -F"=" '$1~/^ftpd_banner/{print $2}' $Filename 2>/dev/null`
  tmp6=`echo $tmp6 |awk '$0~/Authorized.*users.*only.*/'`
  if [ "$tmp1" = "YES" ] &&  [ "$tmp2" = "YES" ] &&  [ "$tmp3" = "022" ] &&  [ "$tmp4" = "022" ]  &&  [ "$tmp5" = "YES" ]  && [ -n "$tmp6" ]; then
      echo "[OK] $Filename #"
  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
       if [ -z "$tmp1" ] ; then
         echo "write_enable=YES" >>$Filename
       fi
       if [ -z "$tmp2" ] ; then
         echo "ls_recurse_enable=YES" >>$Filename
       fi
       if [ -z "$tmp3" ] ; then
         echo "local_umask=022" >>$Filename
       fi
       if [ -z "$tmp4" ] ; then
         echo "anon_umask=022" >>$Filename
       fi
       if [ -z "$tmp5" ] ; then
         echo "chroot_local_user=YES" >>$Filename
       fi
        if [ -z "$tmp6" ] ; then
         echo "ftpd_banner=\"Authorized users only. All activity will be monitored and reported.\"" >>$Filename
       fi
       sed -i 's/^\(write_enable\).*/#&\n\1=YES/g' $Filename;
       sed -i 's/^\(ls_recurse_enable\).*/#&\n\1=YES/g' $Filename;
       sed -i 's/^\(local_umask\).*/#&\n\1=022/g' $Filename;
       sed -i 's/^\(anon_umask\).*/#&\n\1=022/g' $Filename;
       sed -i 's/^\(chroot_local_user\).*/#&\n\1=YES/g' $Filename;
       sed -i 's/^\(ftpd_banner\).*/#&\n\1=\"Authorized users only. All activity will be monitored and reported.\"/g' $Filename;
       if [ ! -e  "$Filename2" ] ; then
          ln -s $Filename $Filename2;
       fi
       echo "[Fix]$Filename#"
    else
     echo "[Not] $Filename #"
    fi
  fi
##如果系统使用pure-ftp
##修改/etc/pure-ftpd/pure-ftpd.conf
### vi /etc/pure-ftpd/pure-ftpd.conf
##确保以下行未被注释掉，如果没有该行，请添加：
##Umask                       177:077
##重启ftp服务
###/etc/init.d/pure-ftpd restart

##2.pure-ftp
##修改/etc/pure-ftpd/pure-ftpd.conf
###vi /etc/pure-ftpd/pure-ftpd.conf
##确保以下行未被注释掉（并且值为以下值），如果没有该行，请添加：
##ChrootEveryone              yes
##AllowUserFXP                no
##AllowAnonymousFXP           no
##重启ftp服务
###/etc/init.d/pure-ftpd restart"
##

##2.修改pure-ftp配置文件：
###vi /etc/pure-ftpd/pure-ftpd.conf
##找到以下行，确保该行未被注释。
##FortunesFile   /usr/share/fortune/zippy
##编辑/usr/share/fortune/zippy文件（如没有fortune文件夹或者zippy文件，则新建该文件夹或该文件）：
###vi /usr/share/fortune/zippy
##将自定义BANNER写入其中。
##重启服务：
### /etc/init.d/pure-ftpd restart

  Filename="/etc/pure-ftpd/pure-ftpd.conf"
  sub_switch="on"

if [ -e "$Filename" ] ; then
  tmp1=`awk '$1~/Umask/{print $2}' $Filename 2>/dev/null`
  tmp2=`awk '$1~/ChrootEveryone/{print $2}' $Filename 2>/dev/null`
  tmp3=`awk '$1~/AllowUserFXP/{print $2}' $Filename 2>/dev/null`
  tmp4=`awk '$1~/AllowAnonymousFXP/{print $2}' $Filename 2>/dev/null`
  tmp5=`awk '$1~/FortunesFile/{print $2}' $Filename 2>/dev/null`
  if [ "$tmp1" = "177:077" ] && [ "$tmp2" = "yes" ] && [ "$tmp3" = "no" ] && [ "$tmp4" = "no" ] && [ "$tmp5" = "/usr/share/fortune/zippy" ]; then
      echo "[OK] $Filename #"
  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
       if [ -z "$tmp1" ] ; then
         echo "Umask      177:077" >>$Filename
       fi
       if [ -z "$tmp2" ] ; then
         echo "ChrootEveryone              yes" >>$Filename
       fi
       if [ -z "$tmp3" ] ; then
         echo "AllowUserFXP                no" >>$Filename
       fi
       if [ -z "$tmp4" ] ; then
         echo "AllowAnonymousFXP           no" >>$Filename
       fi
       if [ -z "$tmp5" ] ; then
         echo "FortunesFile   /usr/share/fortune/zippy" >>$Filename
       fi
       if [ -e  "/usr/share/fortune/zippy" ] ; then
          mkdir -p /usr/share/fortune/ 2>/dev/null
         touch /usr/share/fortune/zippy 2>/dev/null;
       fi
       sed -i 's/^\(Umask\).*/#&\n\1\t177:077/g' $Filename;
       sed -i 's/^\(ChrootEveryone\).*/#&\n\1\tyes/g' $Filename;
       sed -i 's/^\(AllowUserFXP\).*/#&\n\1\tno/g' $Filename;
       sed -i 's/^\(AllowAnonymousFXP\).*/#&\n\1\tno/g' $Filename;
       sed -i 's/^\(FortunesFile\).*/#&\n\1\t\/usr\/share\/fortune\/zippy/g' $Filename;
       echo "[Fix]$Filename#"
    else
     echo "[Not] $Filename #"
    fi
  fi
else
  echo "[Err]$Filename not exist";
fi







}

linux_sub_snmp(){
#编辑/etc/snmp/snmpd.conf，修改private默认团体字为用户自定义团体字。
#如果系统安装了snmp服务，请确保该文件存在。如果不存在，则在/etc/snmp/目录下创建该文件。
#编辑/etc/snmp/snmpd.conf，修改public默认团体字为用户自定义团体字。
  Filename="/etc/snmp/snmpd.conf"
  sub_switch="on"

  PRL=`egrep '^[^#].*public.*'  $Filename 2>/dev/null |tail -1`;
  if [ -z "$PRL" ] ; then
    echo "[OK]$Filename public#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      sed  -i 's/\(^[^#].*\)public\(.*\)/\1MM@snmp2015\2/g'  $Filename;
      echo "[Fix]$Filename public";
    else
      echo "[Not]$Filename public" 
    fi
  fi


}

linux_sub_issue(){
#echo " Authorized users only. All activity may be monitored and reported " > /etc/issue
#echo " Authorized users only. All activity may be monitored and reported " > /etc/issue.net
#
  Filename="/etc/issue"
  sub_switch="on"

  PRL=`egrep 'Authorized users only' $Filename 2>/dev/null |tail -1`;
  if [ -n "$PRL" ] ; then
    echo "[OK]$Filename #"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      if [ -z "$PRL" ] ; then
        echo " Authorized users only. All activity may be monitored and reported "> $Filename;
      fi
      echo "[Fix]$Filename #";
    else
      echo "[Not]$Filename #" 
    fi
  fi


    Filename="/etc/issue.net"
  sub_switch="on"

  PRL=`egrep 'Authorized users only' $Filename 2>/dev/null |tail -1`;
  if [ -n "$PRL" ] ; then
    echo "[OK]$Filename #"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      if [ -z "$PRL" ] ; then
         echo " Authorized users only. All activity may be monitored and reported "> $Filename
      fi
      echo "[Fix]$Filename #";
    else
      echo "[Not]$Filename #" 
    fi
  fi




}
linux_sub_findrhost(){
###"1.执行命令find / -maxdepth 3 -type f -name .rhosts 2>/dev/null
##2.进入到.rhosts文件存在的目录
##3.执行命令：mv .rhosts .rhosts.bak "
##"1.执行命令find / -maxdepth 3 -name hosts.equiv 2>/dev/null
##2.进入到hosts.equiv文件存在的目录
##3.执行命令：mv hosts.equiv hosts.equiv.bak"
Filename=`find / -maxdepth 3 -type f -name .rhosts 2>/dev/null`
sub_switch="on"

if [ -z "$Filename" ] ; then
  echo "[OK].rhosts #"
else
  if [ "$sub_switch" = "on" ] ; then
    mv -f $Filename $Filename".bak"
    echo "[Fix] $Filename #";
  else
    echo "[Not]$Filename #"
  fi
fi

Filename=`find / -maxdepth 3 -name hosts.equiv 2>/dev/null`
sub_switch="on"

if [ -z "$Filename" ] ; then
  echo "[OK]hosts.equiv #"
else
  if [ "$sub_switch" = "on" ] ; then
    mv -f $Filename $Filename".bak"
    echo "[Fix] $Filename #";
  else
    echo "[Not]$Filename #"
  fi
fi


}
linux_sub_logfile_chmod(){
##"1.如果为redhat，suse9,则备份/etc/syslog.conf(或/etc/rsyslog.conf)文件中配置的日志文件，如果为suse10，suse11，则备份/etc/syslog-ng文件中配置的日志文件.
##2.如果日志服务为syslogd，则执行：
##    LOGDIR=`cat /etc/syslog.conf 2>/dev/null | grep -v ""^[[:space:]]*#""|sed '/^#/d' |sed '/^$/d' |awk '(($2!~/@/) && ($2!~/*/) && ($2!~/-/)) {print $2}';`;ls -l $LOGDIR 2>/etc/null | grep  ""^-"";跳转至步骤3.
##如果日志服务为syslog-ng，则执行：
##    LOGDIR=`cat /etc/syslog-ng/syslog-ng.conf 2>/dev/null | grep -v ""^[[:space:]]*#""|grep ""^destination""|grep file|cut -d\"" -f2`;ls -l $LOGDIR 2>/dev/null | grep ""^-"";跳转至步骤3.
##如果日志服务为rsyslogd，则执行：
##    LOGDIR=`cat /etc/rsyslog.conf | grep -v ""^[[:space:]]*#"" |sed '/^#/d' |sed '/^$/d' |awk '(($2!~/@/) && ($2!~/*/) && ($2!~/-/)) {print $2}'`;ls -l $LOGDIR 2>/etc/null | grep ""^-"";跳转至步骤3.
##3.步骤2列出的文件中，同组用户、其他用户权限中不能出现r-x,rw-,rwx。
##执行下列命令，修改步骤2中列出出来的不符合标准值的文件权限。
##例如修改权限为640
###chmod 640 <filename>
##或者修改权限为600
###chmod 600 <filename>
##注：权限值没有限定，只要满足同组用户、其他用户不出现r-x,rw-,rwx即可。"
LOGDIR1=`cat /etc/syslog.conf 2>/dev/null | grep -v "^[[:space:]]*#"|sed '/^#/d' |sed '/^$/d' |awk '(($2!~/@/) && ($2!~/*/) && ($2!~/-/)) {print $2}';`;
LOGDIR2=`cat /etc/syslog-ng/syslog-ng.conf 2>/dev/null | grep -v "^[[:space:]]*#"|grep "^destination"|grep file|cut -d\" -f2`;
LOGDIR3=`cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#" |sed '/^#/d' |sed '/^$/d' |awk '(($2!~/@/) && ($2!~/*/) && ($2!~/-/)) {print $2}'`;

AllLog=$LOGDIR1" "$LOGDIR2" "$LOGDIR3

FILE_LIST=`find $AllLog -type f  2>/dev/null`
for i in $FILE_LIST
do
  chmodFile "$i" "640" on;
done

}


hpux_sub_security(){
  #在 /etc/default/security 文件设置,MIN_PASSWORD_LENGTH = 阀值
  Filename="/etc/default/security"
  sub_switch="on"

  PRL=`awk -F"=" '$1~/^MIN_PASSWORD_LENGTH/{print $2}' $Filename|tail -1`;
  if [ "$PRL" -ge "12" ] ; then
    echo "[OK]$Filename MIN_PASSWORD_LENGTH $PRL#"

  else
    if [ $sub_switch = "on" ] ; then
        Backup_file $Filename
      if [ -z "$PRL" ] ; then
        echo "MIN_PASSWORD_LENGTH=12"  >> $Filename;
      else
        sed '/^MIN_PASSWORD_LENGTH.*/s/^/# /' $Filename > /tmp/sedtmp
        echo "MIN_PASSWORD_LENGTH=12"  >> /tmp/sedtmp
        cat /tmp/sedtmp > $Filename;
      fi
      echo "[Fix]$Filename MIN_PASSWORD_LENGTH";
    else
      echo "[Not]$Filename MIN_PASSWORD_LENGTH $PML" 
    fi
  fi



}

hpux_sub_UMASK(){
#在/etc目录下的profile文件尾部增加 umask 027
setUMASK "/etc/profile" "027" on
#在/etc目录下的d.profile文件尾部增加 umask 027
setUMASK "/etc/d.profile" "027" on
#在/etc目录下的d.login文件尾部增加 umask 027
setUMASK "/etc/d.login" "027" on
#在/etc目录下的csh.login文件尾部增加 umask 027
setUMASK "/etc/csh.login" "027" on  


}
hpux_sub_CHMOD(){
#执行命令 ： chmod 600 /etc/shadow
  chmodFile "/etc/shadow" "600" 

}
hpux_sub_ftp(){
#编辑/etc/ftpd/ftpaccess文件，加入如下一行：restricted-uid   *(限制所有用户) 或 restricted-uid   username(限制特定用户)，
  Filename="/etc/ftpd/ftpaccess"
  sub_switch="on"

  tmp=`egrep "^restricted-uid.*" $Filename |tail -1 `
  if [ -n "$tmp" ] ; then
      echo "[OK] $Filename #";
  else
     if [ "$sub_switch" = "on" ] ; then
        if [ ! -e "$Filename" ] ; then
          mkdir -p `dirname $Filename`
          touch $Filename
        fi
          Backup_file $Filename
          echo "restricted-uid  root" >> $Filename;
          echo "[Fix] $Filename # "
     else
       echo "[Not] $Filename #" ; 
     fi
  fi


}



#===============================================================================
# COMMON FUNC
#===============================================================================


Backup_file(){
  if [ $# -lt 1 ] ; then
    return 0;
  fi
  Filename="$1"
  Bak_name="$Filename"_"$DATE"
  
  if [ -e $Filename ] ; then
    echo "$Filename   $Bak_name">> $BackupFileList;

    if [ -s $Bak_name ] ; then
      Bak_name="$Filename"_`date +"%Y%m%d_%H%M%S"`
    fi
    cp -f $Filename $Bak_name;
    
  else
    return 1;
  fi

}

setUMASK(){
  if [ $# -lt 2 ] ; then
    return 0;
  fi

  Filename=$1
  tmp_UMASK=$2
  Results=`grep -i umask $Filename|grep $tmp_UMASK  2>/dev/null `

  if [ -n "$Results" ] ; then
    echo "[OK]$Filename : $Results#"
    return 1;
  else
    if [ "$3" = "on" ] ; then
        Backup_file $Filename;
        echo " umask $tmp_UMASK" >> $Filename 
        echo "[Fix]echo umask $tmp_UMASK >> $Filename#"
    else
        echo "[Not]$Filename#"
    fi

    return 1;
  fi  

}

chmodFile(){
  if [ $# -lt 2 ] ; then
    return 0;
  fi
  Filename=$1
  setToPermission=$2
  
  
  if [ -e $Filename ] ; then
    File_Permission=`LANG=C find $Filename -maxdepth 0 -printf "%m" 2>/dev/null`
    if [ $File_Permission  =  $setToPermission  ] ; then
      echo "[OK]"$Filename" "$File_Permission"#" ;
      return 0;
    fi
    
    if [ "$3" = "on" ] ; then
      echo "chmod $File_Permission $Filename" >> $CHMOD_BackupList; 
      chmod $setToPermission $Filename;
      echo "[Fix]chmod $setToPermission $Filename#"
    else
      echo "[Not]"$Filename" "$File_Permission"#"
    fi
    
  else
    echo "[ERR!]$Filename : No such file or directory"
    return 0;
  fi
}

setSysctl(){
  if [ $# -lt 2 ] ; then
    return 0;
  fi
  Variable="$1"
  Value="$2"
  
  REAL_Value=`sysctl -n $1`
  
  if [ "$REAL_Value" = "$Value"  ] ; then
    echo "[OK]"$Variable" "$REAL_Value"#" ;
    return 0;
  fi
  
   if [ "$3" = "on" ] ; then
      NOWTIME=`date +"%Y%m%d_%H%M%S"`
      #echo $NOWTIME >> $Other_BackupList
      echo "sysctl -w $Variable=$REAL_Value" >> $Other_BackupList;
      sysctl -w "$Variable=$Value" >/dev/null
      echo "[Fix]sysctl -w $Variable $Value #"
    else
      echo "[Not]"$Variable" "$REAL_Value"#"
    fi



}





create_Restore_file(){
  touch $Restore_script; 
  if [ -s $BackupFileList ] ; then
    sort $BackupFileList |uniq |sort |awk '{print "cp -f "$2" "$1}' > $Restore_script
  fi
  if [ -s $CHMOD_BackupList ] ; then
    sort $CHMOD_BackupList |uniq |sort  >> $Restore_script
  fi
  if [ -s $Other_BackupList ] ; then
    sort $Other_BackupList |uniq |sort  >> $Restore_script
  fi
  chmod +x $Restore_script;
  echo "you can use this script for rollback : $Restore_script"; 

}

#===============================================================================
#  MAIN SCRIPT
#===============================================================================

OSType=`uname `
case "$OSType" in
  "Linux")
    RUN_LINUX;
    ;;

  "HP-UX")
    RUN_HPUX;
    ;;

  *)
    ;;

esac    # --- end of case ---



#if [ "$OSType" = "Linux" ] ; then
#echo -n "linux"

#grep -i umask /etc/csh.cshrc
#
#else
# echo "unix"
#fi

#printf "%s\t" $RESULTS
