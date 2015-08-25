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


BackupFileList=/tmp/backupfile_"$DATE".list


#===============================================================================
#  FUNCTION DEFINITIONS
#===============================================================================

RUN_LINUX() 
{
  #echo -n linux
  linux_sub_UMASK;    
  linux_sub_CHMOD;
  linux_sub_syslogng;
  linux_sub_syslog;
  linux_sub_rsyslog;
  linux_sub_setTMOUT;
  linux_sub_pam;
  linux_sub_PassMinLen;
  linux_sub_sshdconfig;
  linux_sub_limit;
  linux_sub_findsuid;
  linux_sub_distelnet;
  linux_sub_disxinetd;

  Restore_file;
  
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
}

linux_sub_CHMOD(){
  #chmod 750 /etc/inetd.conf
  #
  chmodFile "/etc/inetd.conf" "750" on;

  #chmod 750 /tmp
  chmodFile "/tmp" "750" on;

  #chmod 750 /etc/shadow
  chmodFile "/etc/shadow" "750" on;

  # chmod 750 /etc/rc2.d/
  chmodFile "/etc/rc2.d/" "750" on

  #chmod 700 /etc/ssh/ssh_host_dsa_key
  chmodFile "/etc/ssh/ssh_host_dsa_key" "700" on;

  #chmod 750 /etc/rc5.d/
  chmodFile "/etc/rc5.d/" "750" on;

  #chmod 755 /etc/group
  chmodFile "/etc/group" "755" on;

  #chmod 750 /etc/rc1.d/
  chmodFile "/etc/rc1.d/" "750" on;

  #chmod 750 /etc/rc6.d/
  chmodFile "/etc/rc6.d/" "750" on;

  #chmod 750 /etc/services
  chmodFile "/etc/services" "750" on;

  #chmod 750 /etc/rc.d/init.d/
  chmodFile "/etc/rc.d/init.d/" "750" on;

  #chmod 750 /etc/rc3.d/
  chmodFile "/etc/rc3.d/" "750" on;

  #chmod 750 /etc/rc4.d/
  chmodFile "/etc/rc4.d/" "750" on;

  #chmod 750 /etc/rc0.d/
  chmodFile "/etc/rc4.d/" "750" on;

  #chmod 755 /etc/passwd
  chmodFile "/etc/passwd" "755" on;

  #chmod 700 /etc/ssh/ssh_host_rsa_key
  chmodFile "/etc/ssh/ssh_host_rsa_key" "700" on;

  #chmod 750 /etc/
  chmodFile "/etc/" "750" on;

}
linux_sub_syslogng(){
#在/etc/syslog-ng/syslog-ng.conf中配置destination logserver { udp("10.10.10.10" port(514)); };
#log { source(src); destination(logserver); };
#可以将此处10.10.10.10替换为实际的IP
  Log_server="10.101.1.61"
  Filename="/etc/syslog-ng/syslog-ng.conf"
  sub_switch="off"

  if [ $sub_switch = "on" ] ; then
    if [ -e $Filename] ; then
      Backup_file $Filename
    fi
    echo "destination logserver { udp("$Log_server" port(514)); };" >> $Filename;
    echo "log { source(src); destination(logserver); };" >> $Filename;
    echo "[change]$Filename#"
  else
    tmp=`grep "destination logserver" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[ok] $Filename #"
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
  sub_switch="off"

  if [ $sub_switch = "on" ] ; then
    if [ -e $Filename] ; then
      Backup_file $Filename
    fi
    echo "*.*                    @"$Log_server >> $Filename;
    echo "[change]$Filename#"
  else
    tmp=`grep "@$Log_server" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[ok] $Filename #"
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
  sub_switch="off"

  if [ $sub_switch = "on" ] ; then
    if [ -e $Filename] ; then
      Backup_file $Filename
    fi
    echo "*.*                    @"$Log_server >> $Filename;
    echo "[change]$Filename#"
  else
    tmp=`grep "@$Log_server" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[ok] $Filename #"
    else
      echo "[Not] $Filename #"
    fi
  fi
}
linux_sub_setTMOUT(){
#以root账户执行，vi /etc/profile,增加 export TMOUT=180(单位：秒，可根据具体情况设定超时退出时间，要求不小于180秒),注销用户，再用该用户登录激活该功能
  Filename="/etc/profile"
  sub_switch="off"

  if [ $sub_switch = "on" ] ; then
    if [ -e $Filename] ; then
      Backup_file $Filename
    fi
    echo "export TMOUT=180" >> $Filename;
    echo "[change]$Filename#"
  else
    tmp=`grep "TMOUT=180" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[ok] $Filename #"
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
  sub_switch="off"

  if [ $sub_switch = "on" ] ; then
    if [ -e $Filename] ; then
      Backup_file $Filename
    fi
    echo "#auth  required  pam_tally.so deny=10 unlock_time=300 no_lock_time" >> $Filename;
    echo "#account  required   pam_tally.so">> $Filename;
    echo "password  requisite pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1" >> $Filename
    echo "[change]$Filename#"
  else
    tmp=`grep "unlock_time=300" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[ok] $Filename #"
    else
      echo "[Not] $Filename #"
    fi
  fi

#Redhat系统：修改/etc/pam.d/system-auth文件,
#在ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 选3种，追加到password  requisite pam_cracklib.so后面，添加到配置文件中。
#例如：password  requisite pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1
#注：ucredit：大写字母个数；lcredit：小写字母个数；dcredit：数字个数；ocredit：特殊字符个数

  Filename="/etc/pam.d/system-auth"
  sub_switch="off"

  if [ $sub_switch = "on" ] ; then
    if [ -e $Filename] ; then
      Backup_file $Filename
    fi
    echo "password  requisite pam_cracklib.so ucredit=-1 lcredit=-1 dcredit=-1" >> $Filename
    echo "[change]$Filename#"
  else
    tmp=`egrep "pam_cracklib.so.*credit" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[ok] $Filename #"
    else
      echo "[Not] $Filename #"
    fi

  #编辑 /etc/pam.d/login文件，配置auth required pam_securetty.so
  Filename="/etc/pam.d/login"
  sub_switch="off"

  if [ $sub_switch = "on" ] ; then
    if [ -e $Filename] ; then
      Backup_file $Filename
    fi
    echo "#auth required pam_securetty.so" >> $Filename;
    echo "[change]$Filename#"
  else
    tmp=`grep "pam_securetty.so" $Filename 2>/dev/null`
    if [ -n "$tmp" ] ; then
      echo "[ok] $Filename #"
    else
      echo "[Not] $Filename #"
    fi
  fi


}

linux_sub_PassMinLen(){
#在文件/etc/login.defs中设置 PASS_MIN_LEN 不小于标准值
  Filename="/etc/login.defs"
  sub_switch="off"
  
  PML=`egrep '^PASS_MIN_LEN' $Filename|awk '{print $NF}' 2>/dev/null`
  if [ "$PML" -ge  12 ]  ; then
    echo "[ok]$Filename PASS_MIN_LEN $PML#"
    return 0;
  fi

  if [ $sub_switch = "on" ] ; then
    if [ -e $Filename] ; then
      Backup_file $Filename
    fi
      sed -i 's/^\(PASS_MIN_LEN\).*/#&\n\1\t12/' $Filename;
      echo "[change]$Filename PASS_MIN_LEN";
  else
      echo "[Not]$Filename PASS_MIN_LEN $PML" 
  fi

}


linux_sub_sshdconfig(){

#修改/etc/ssh/sshd_config文件,配置PermitRootLogin no。

  Filename="/etc/ssh/sshd_config"
  sub_switch="off"

   PRL=`awk '$1~/^PermitRootLogin/{print $2}' $Filename`;
  if [ "$PRL" = "no" ] ; then
    echo "[ok]$Filename PermitRootLogin $PRL#"

  else
    if [ $sub_switch = "on" ] ; then
      if [ -e $Filename] ; then
        Backup_file $Filename
      fi

      sed -i 's/^\(PermitRootLogin\).*/#&\n\1\tno/' $Filename;
      echo "[change]$Filename PermitRootLogin";
    else
      echo "[Not]$Filename PermitRootLogin $PML" 
    fi
  fi

#Protocol 2
  Filename="/etc/ssh/sshd_config"
  sub_switch="off"

   PRL=`awk '$1~/^Protocol/{print $2}' $Filename|head -1 `;
  if [ "$PRL" = "2" ] ; then
    echo "[ok]$Filename Protocol $PRL#"

  else
    if [ $sub_switch = "on" ] ; then
      if [ -e $Filename] ; then
        Backup_file $Filename
      fi

      sed -i 's/^\(Protocol\).*/#&\n\1\t2/' $Filename;
      echo "[change]$Filename Protocol";
    else
      echo "[Not]$Filename Protocol $PML" 
    fi
  fi


}

linux_sub_limit(){
#在文件/etc/security/limits.conf中配置* soft core 0
  Filename="/etc/security/limits.conf"
  sub_switch="off"

   PRL=`awk '$0~/^*.*soft.*core/' $Filename|wc -l`;
  if [ $PRL -gt 0 ] ; then
    echo "[ok]$Filename soft core#"

  else
    if [ $sub_switch = "on" ] ; then
      if [ -e $Filename] ; then
        Backup_file $Filename
      fi

      echo  "* soft core 0" >> $Filename;
      echo "[change]$Filename soft core";
    else
      echo "[Not]$Filename soft core " 
    fi
  fi


#在文件/etc/security/limits.conf中配置* hard core 0
  Filename="/etc/security/limits.conf"
  sub_switch="off"

   PRL=`awk '$0~/^*.*hard.*core/' $Filename|wc -l`;
  if [ $PRL -gt 0 ] ; then
    echo "[ok]$Filename hard core#"

  else
    if [ $sub_switch = "on" ] ; then
      if [ -e $Filename] ; then
        Backup_file $Filename
      fi

      echo  "* hard core 0" >> $Filename;
      echo "[change]$Filename hard core";
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
  Results=`LANG=C find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport -type f -perm +6000 2>/dev/null`
  sub_switch="off"
  
  if [ -n "$Results" ] ; then
    
    if [ "$sub_switch" = "on" ] ; then
      for i in "$Results" ; do
        chmod a-s $i
      done
      echo "[change]chmod-suid"
    else
      echo "[Not]chmod-suid"
    fi

  else
    echo "[OK]chmod-suid"
  fi

}

linux_sub_distelnet(){

#在/etc/services文件中，注释掉 telnet        23/tcp 一行(如不生效重启telnetd服务或xinetd服务或系统，例如，Red Hat 上重启xinetd：service xinetd restart，根据实际情况操作)
  
  Filename="/etc/services"
  sub_switch="off"

   tmp=`egrep "^telnet.*23\/tcp" $Filename 2>/dev/null`
  if [ -z "$tmp" ] ; then
      echo "[ok] $Filename #"
  else
    if [ $sub_switch = "on" ] ; then
      if [ -e $Filename] ; then
        Backup_file $Filename
      fi
       sed -i 's/^telnet.*23.*tcp/#&/g' $Filename;
      echo "[change]$Filename#"
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
    sub_switch="off"
     if [ $sub_switch = "on" ] ; then
     
       for i in "chargen-dgram daytime-stream echo-streamklogin  tcpmux-server chargen-stream  discard-dgram   eklogin  krb5-telnet  tftp cvs  discard-stream  ekrb5-telnet  kshell  time-dgram daytime-dgram   echo-dgram gssftp  rsync  time-stream" ; do
       
       chkconfig $i off 
       
       
       done
     fi


}


#===============================================================================
# sub  
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
    cp $Filename $Bak_name;
    
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
        echo " umask $tmp_UMASK" >> $Filename;
        echo "[change]echo umask $tmp_UMASK >> $Filename#"
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
      chmod $setToPermission $Filename;
      echo "[change]chmod $setToPermission $Filename#"
    else
      echo "[Not]"$Filename" "$File_Permission"#"
    fi
    
  else
    echo "[ERR!]$Filename : No such file or directory"
    return 0;
  fi
}

Restore_file(){
  
  if [ -s $BackupFileList ] ; then
    sort $BackupFileList |uniq |sort |awk 'print "cp -f $2 $1"' > /tmp/run_restore.sh
  fi


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
