#!/usr/bin/env bash
set -euo pipefail

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+/Debian 6+/Ubuntu 14.04+
#	Description: Install the ShadowsocksR mudbjson server
#	Version: 1.0.29
#	Author: Toyo
#	Rewriter: MTimer
#=================================================

sh_ver="1.0.29"
jq_ver="1.6"
libso_ver_default="1.0.17"
SH_FILE="/usr/local/bin/ssr"
SSR_PATH="/usr/local/shadowsocksr"
CONFIG_FILE="$SSR_PATH/config.json"
USERMYSQL_FILE="$SSR_PATH/usermysql.json"
USER_CONFIG_FILE="$SSR_PATH/user-config.json"
USER_API_CONFIG_FILE="$SSR_PATH/userapiconfig.py"
MUDB_FILE="$SSR_PATH/mudb.json"
JQ_FILE="$SSR_PATH/jq"
SSR_LOG_FILE="$SSR_PATH/ssserver.log"
BBR_FILE="$HOME/bbr.sh"
SERVER_SPEEDER_FILE="/serverspeeder/bin/serverSpeeder.sh"
LOTSERVER_FILE="/appex/bin/serverSpeeder.sh"

green="\033[32m"
red="\033[31m"
green_background="\033[42;37m"
red_background="\033[41;37m"
plain="\033[0m"
info="${green}[信息]$plain"
error="${red}[错误]$plain"
tip="${green}[注意]$plain"
separator="——————————————————————————————"

[ $EUID -ne 0 ] && echo -e "[$error] 当前账号非ROOT(或没有ROOT权限),无法继续操作,请使用$green_background sudo su $plain来获取临时ROOT权限（执行后会提示输入当前账号的密码）." && exit 1

CheckRelease()
{
	if grep -Eqi "(Red Hat|CentOS|Fedora|Amazon)" < /etc/issue ; then
		release="rpm"
	elif grep -Eqi "Debian" < /etc/issue ; then
		release="deb"
	elif grep -Eqi "Ubuntu" < /etc/issue ; then
		release="ubu"
	else
		if grep -Eqi "(redhat|centos|Red\ Hat)" < /proc/version ; then
			release="rpm"
		elif grep -Eqi "debian" < /proc/version ; then
			release="deb"
		elif grep -Eqi "ubuntu" < /proc/version ; then
			release="ubu"
		fi
	fi

	if [ -s "/etc/redhat-release" ]; then
		release_ver=$(grep -oE  "[0-9.]+" /etc/redhat-release)
	else
		release_ver=$(grep -oE  "[0-9.]+" /etc/issue)
	fi
	release_ver_main=${release_ver%%.*}

	if [ "$(uname -m | grep -c 64)" -gt 0 ]; then
		release_bit="64"
	else
		release_bit="32"
	fi

	depends=(wget unzip vim curl cron crond python)
	for depend in "${depends[@]}"; do
		DEPEND_PATH="$(command -v "$depend" || true)"
		if [ -z "$DEPEND_PATH" ]; then
			case "$release" in
				"rpm")
					if [ "$depend" != "cron" ]; then
						yum -y install "$depend" >/dev/null 2>&1
					fi
				;;
				"deb"|"ubu")
					if [ "$depend" != "crond" ]; then
						apt-get -y install "$depend" >/dev/null 2>&1
					fi
				;;
				*) echo -e "\n系统不支持!" && exit 1
				;;
			esac
			
		fi
	done

	[ ! "$(wget -V)" ] && echo -e "$error 依赖 wget 安装失败..." && exit 1
	[ ! "$(unzip -v)" ] && echo -e "$error 依赖 unzip 安装失败..." && exit 1
	[ ! "$(curl -V)" ] && echo -e "$error 依赖 curl 安装失败..." && exit 1
	[ ! "$(ls /usr/sbin/cron*)" ] && echo -e "$error 依赖 cron 安装失败..." && exit 1
}

ChangeDate(){
	rm -rf /etc/localtime
	ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}

RestartCron(){
	case "$release" in
		"rpm") /etc/init.d/crond restart
		;;
		"deb") /etc/init.d/cron restart
		;;
		*) echo "$error 重启cron发生错误!"
		;;
	esac
}

InstallSsr(){
	echo -e "$info 开始下载/安装 ShadowsocksR文件..."
	wget --no-check-certificate "https://github.com/woniuzfb/shadowsocksr/archive/manyuser.zip" -qO manyuser.zip
	[ ! -e "./manyuser.zip" ] && echo -e "$error ShadowsocksR服务端 压缩包 下载失败 !" && exit 1
	unzip "./manyuser.zip" && rm -rf "./manyuser.zip"
	[ ! -e "./shadowsocksr-manyuser/" ] && echo -e "$error ShadowsocksR服务端 解压失败 !" && exit 1
	mv "./shadowsocksr-manyuser" "$SSR_PATH"
	[ ! -d "$SSR_PATH" ] && echo -e "$error 移动 ShadowsocksR服务端 失败 !" && exit 1

	cp "$SSR_PATH/config.json" "$CONFIG_FILE"
	cp "$SSR_PATH/mysql.json" "$USERMYSQL_FILE"
	cp "$SSR_PATH/apiconfig.py" "$USER_API_CONFIG_FILE"
	[ ! -e "$USER_API_CONFIG_FILE" ] && echo -e "$error ShadowsocksR服务端 apiconfig.py 复制失败 !" && exit 1

	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" "$USER_API_CONFIG_FILE"
	sed -i 's/ \/\/ only works under multi-user mode//g' "$USER_CONFIG_FILE"
	echo -e "$info ShadowsocksR服务端 下载完成 !"

	if wget --no-check-certificate https://raw.githubusercontent.com/woniuzfb/doubi/master/ssrmu.init -qO /etc/init.d/ssrmu; then
        chmod +x /etc/init.d/ssrmu
        case "$release" in
            "rpm")
                chkconfig --add ssrmu
                chkconfig ssrmu on
            ;;
            "deb")
                update-rc.d -f ssrmu defaults
            ;;
            *) echo -e "$error 系统不支持 !" && exit 1
            ;;
        esac
        echo -e "$info ShadowsocksR服务 管理脚本下载完成 !"
    else
        echo -e "$error ShadowsocksR服务 管理脚本下载失败 !" && exit 1
    fi
}

UninstallSsr(){
	[ ! -e "$SSR_PATH" ] && echo -e "$error 没有安装 ShadowsocksR，请检查 !" && exit 1
	CheckRelease
	echo "确定要 卸载ShadowsocksR？[y/N]" && echo
	read -p "(默认: n):" uninstall_ssr_yn
	[ -z "$uninstall_ssr_yn" ] && uninstall_ssr_yn="n"
	if [[ "$uninstall_ssr_yn" == [Yy] ]]; then
		StopSsr
		GetAccsInfo
		for acc_port in "${accs_port[@]}"; do
			DelIptables
		done
		if crontab -l | grep -q "ssrmu.sh"; then
			ClearTransferAllCronStop
		fi
		if [ "$release" = "rpm" ]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf "$SSR_PATH" && rm -rf /etc/init.d/ssrmu
		echo && echo " ShadowsocksR 卸载完成 !" && echo
	else
		echo && echo " 卸载已取消..." && echo
	fi
}

InstallJq(){
	if [ ! -e "$JQ_FILE" ]; then
		echo -e "$info 开始下载/安装 JSNO解析器 JQ..."
		#experimental# grep -Po '"tag_name": "jq-\K.*?(?=")'
		jq_ver=$(curl --silent -m 10 "https://api.github.com/repos/stedolan/jq/releases/latest" |  grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
		if [ -n "$jq_ver" ]; then
			wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-$jq_ver/jq-linux$release_bit" -qO "$JQ_FILE"
		else
			mv "$SSR_PATH/jq-linux$release_bit" "$JQ_FILE"
		fi
		[ ! -e "$JQ_FILE" ] && echo -e "$error 下载JQ解析器失败，请检查 !" && exit 1
		chmod +x "$JQ_FILE"
		echo -e "$info JQ解析器 安装完成..." 
	else
		echo -e "$info JQ解析器 已安装..."
	fi
}

GetServerIp(){
    server_ip=$( ip addr | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -E -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z "$server_ip" ] && server_ip=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z "$server_ip" ] && server_ip=$( wget -qO- -t1 -T2 ipinfo.io/ip )
	[ -z "$server_ip" ] && server_ip=$( wget -qO- -t1 -T2 api.ip.sb/ip )
    [ -z "$server_ip" ] && echo "无法获取本机IP，请手动输入" && exit 1
}

SetServerName(){
	echo "请输入 服务器IP或域名
默认为本机外网IP，如果要自动检测外网IP，请留空直接回车"
	read -p "(默认: 本机IP):" server_name
	[ -z "$server_name" ] && GetServerIp && server_name=$server_ip
	sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '$server_name'/" "$USER_API_CONFIG_FILE"
	echo && echo -e "	IP/域名: $red_background $server_name $plain" && echo
}

RandAccUser(){
	name_size=8
	name_array=(
		q w e r t y u i o p a s d f g h j k l z x c v b n m Q W E R T Y U I O P A S D
F G H J K L Z X C V B N M
	)
	name_array_size=${#name_array[*]}
	name_len=0
	acc_user=""
	while :;do
		while [ $name_len -lt $name_size ]; do
			name_index=$((RANDOM%name_array_size))
			acc_user="$acc_user${name_array[$name_index]}"
			((name_len++))
		done
		acc_info=$($JQ_FILE '.[]|select(.user=="'"$acc_user"'")' $MUDB_FILE)
		if [ -z "$acc_info" ]; then
			break
		fi
	done
}

SetAccUser(){
	echo "请输入要设置的用户 用户名(请勿重复, 用于区分, 不支持中文、空格, 会报错 !)"
	while read -p "(默认: 随机):" acc_user; do
		acc_user=${acc_user// /}
		if [ -z "$acc_user" ]; then
			RandAccUser
			break
		else
			acc_info=$($JQ_FILE '.[]|select(.user=="'"$acc_user"'")' $MUDB_FILE)
			if [ -z "$acc_info" ]; then
				break
			else
				echo -e "$error 用户名已存在！请重新输入！ "
			fi
		fi
	done
	echo && echo "$separator" && echo -e "	用户名 : $green$acc_user$plain" && echo "$separator" && echo
}

GetFreePort(){
    read lowerport upperport < /proc/sys/net/ipv4/ip_local_port_range
    while :;do
            acc_port=$(shuf -i "$lowerport"-"$upperport" -n 1)
            ss -lpn | grep -q ":$acc_port " || break
    done
    # OR acc_port=$(python -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()');
}

SetAccPort(){
	echo "请输入要设置的用户 端口(请勿重复, 用于区分)"
	while read -p "(默认: 随机生成):" acc_port; do
		case "$acc_port" in
			("")
				GetFreePort
				break
			;;
			(*[!0-9]*)
				echo -e "$error 请输入正确的数字！(1-65535) "
			;;
			(*)
				if [ "$acc_port" -ge 1 ] && [ "$acc_port" -le 65535 ]; then
					acc_info=$($JQ_FILE '.[]|select(.port=="'"$acc_port"'")' $MUDB_FILE)
					if [ -z "$acc_info" ]; then
						if ss -lpn | grep -q ":$acc_port "; then
							echo -e "$error 端口已被其他程序占用！请重新输入！ "
						else
							echo && echo $separator && echo -e "	端口: $green $acc_port $plain" && echo $separator && echo
							break
						fi
					else
						echo -e "$error 端口已被其他用户占用！请重新输入！ "
					fi
				else
					echo -e "$error 请输入正确的数字！(1-65535) "
				fi
			;;
		esac
	done
}

RandPasswd(){
	pass_size=10
	pass_array=(
		q w e r t y u i o p a s d f g h j k l z x c v b n m Q W E R T Y U I O P A S D
F G H J K L Z X C V B N M ! @
	)
	pass_array_size=${#pass_array[*]}
	pass_len=0
	acc_passwd=""
	while [ $pass_len -lt $pass_size ]; do
		pass_index=$((RANDOM%pass_array_size))
		acc_passwd="$acc_passwd${pass_array[$pass_index]}"
		((pass_len++))
	done
}

SetAccPasswd(){
	echo "请输入要设置的用户 密码"
	read -p "(默认: 随机生成):" acc_passwd
	[ -z "$acc_passwd" ] && RandPasswd
	echo && echo "$separator" && echo -e "	密码 : $green$acc_passwd$plain" && echo "$separator" && echo
}

SetAccMethod(){
	echo -e "请选择要设置的用户 加密方式
	
  ${green}1.$plain none
 $tip 如果使用 auth_chain_* 系列协议，建议加密方式选择 none (该系列协议自带 RC4 加密)，混淆随意
 
  ${green}2.$plain rc4
  ${green}3.$plain rc4-md5
  ${green}4.$plain rc4-md5-6
 
  ${green}5.$plain aes-128-ctr
  ${green}6.$plain aes-192-ctr
  ${green}7.$plain aes-256-ctr
 
  ${green}8.$plain aes-128-cfb
  ${green}9.$plain aes-192-cfb
 ${green}10.$plain aes-256-cfb
 
 ${green}11.$plain aes-128-cfb8
 ${green}12.$plain aes-192-cfb8
 ${green}13.$plain aes-256-cfb8
 
 ${green}14.$plain salsa20
 ${green}15.$plain chacha20
 ${green}16.$plain chacha20-ietf
 $tip salsa20/chacha20-*系列加密方式，需要额外安装依赖 libsodium ，否则会无法启动ShadowsocksR !" && echo
	read -p "(默认: 10. aes-256-cfb):" acc_method_number
	acc_method_array=(
		none rc4 rc4-md5 rc4-md5-6 aes-128-ctr 
		aes-192-ctr aes-256-ctr aes-128-cfb aes-192-cfb 
		aes-256-cfb  aes-128-cfb8 aes-192-cfb8 aes-256-cfb8 
		salsa20 chacha20 chacha20-ietf 
	)
	acc_method=${acc_method_array["$acc_method_number" - 1]}
	[ -z "$acc_method" ] && acc_method=${acc_method_array[9]}
	echo && echo "$separator" && echo -e "	加密 : $green$acc_method$plain" && echo "$separator" && echo
}

SetAccProtocol(){
	echo -e "请选择要设置的用户 协议插件
	
 ${green}1.$plain origin
 ${green}2.$plain auth_sha1_v4
 ${green}3.$plain auth_aes128_md5
 ${green}4.$plain auth_aes128_sha1
 ${green}5.$plain auth_chain_a
 ${green}6.$plain auth_chain_b
 $tip 如果使用 auth_chain_* 系列协议，建议加密方式选择 none (该系列协议自带 RC4 加密)，混淆随意" && echo
	read -e -p "(默认: 4. auth_aes128_sha1):" protocol_number
	protocol_array=(
		origin 
		auth_sha1_v4 
		auth_aes128_md5 
		auth_aes128_sha1 
		auth_chain_a
		auth_chain_b
	)
	acc_protocol=${protocol_array["$protocol_number" - 1]}
	[ -z "$acc_protocol" ] && acc_protocol=${protocol_array[3]}
	if [ "$acc_protocol" == "auth_sha1_v4" ]; then
        read -p "是否设置 协议插件兼容原版(_compatible)？[Y/n 默认否]" protocol_yn
        [ -z "$protocol_yn" ] && protocol_yn="n"
        [[ $protocol_yn == [Yy] ]] && acc_protocol=$acc_protocol"_compatible"
        echo
	fi
	echo && echo "$separator" && echo -e "	协议 : $green$acc_protocol$plain" && echo "$separator" && echo
}

SetAccProtocolParam(){
	echo -e "请输入要设置的用户 欲限制的设备数 ($green auth_* 系列协议 不兼容原版才有效 $plain)"
	echo -e "$tip 设备数限制：每个端口同一时间能链接的客户端数量(多端口模式，每个端口都是独立计算)，建议最少 2个。"
	while read -p "(默认: 无限):" acc_protocol_param; do
        case "$acc_protocol_param" in
            ("")
                break
            ;;
            (*[!0-9]*)
                echo -e "$error 请输入正确的数字(1-9999) "
            ;;
            (*)
                if [ "$acc_protocol_param" -ge 1 ] && [ "$acc_protocol_param" -le 9999 ]; then
                    break
                else
                    echo -e "$error 请输入正确的数字(1-9999)"
                fi
            ;;
        esac
    done
    [ "$acc_protocol_param" == "" ] && acc_protocol_param_text="无限" || acc_protocol_param_text="$acc_protocol_param"
    echo && echo "$separator" && echo -e "	设备数限制 : $green$acc_protocol_param_text$plain" && echo "$separator" && echo
}

SetAccObfs(){
	echo -e "请选择要设置的用户 混淆插件
	
 ${green}1.$plain plain
 ${green}2.$plain http_simple
 ${green}3.$plain http_post
 ${green}4.$plain random_head
 ${green}5.$plain tls1.2_ticket_auth
 $tip 如果使用 ShadowsocksR 代理游戏，建议选择 混淆兼容原版或 plain 混淆，然后客户端选择 plain，否则会增加延迟 !
 另外, 如果你选择了 tls1.2_ticket_auth，那么客户端可以选择 tls1.2_ticket_fastauth，这样即能伪装又不会增加延迟 !
 如果你是在日本、美国等热门地区搭建，那么选择 plain 混淆可能被墙几率更低 !" && echo
	read -p "(默认: 5. tls1.2_ticket_auth):" obfs_number
	obfs_array=(
		plain 
		http_simple 
		http_post 
		random_head 
		tls1.2_ticket_auth
	)
	acc_obfs=${obfs_array["$obfs_number" - 1]}
	[ -z "$acc_obfs" ] && acc_obfs=${obfs_array[4]}
	if [ "$acc_obfs" != "plain" ]; then
        read -p "是否设置 混淆插件兼容原版(_compatible)？[Y/n 默认否]" obfs_compa_yn
        [ -z "$obfs_compa_yn" ] && obfs_compa_yn="n"
        [[ "$obfs_compa_yn" == [Yy] ]] && acc_obfs=$acc_obfs"_compatible"
	fi
	echo && echo "$separator" && echo -e "	混淆 : $green$acc_obfs$plain" && echo "$separator" && echo
}

SetAccObfsParam(){
	echo -e "请输入要设置的混淆参数 ($green 伪装 $plain)"
	read -p "(默认: 随机):" acc_obfs_param
	[ -z "$acc_obfs_param" ] && acc_obfs_param=$(echo a"$(od -An -N2 -i /dev/random)" | sed 's/ //g')."wns.windows.com"
	echo "$separator" && echo -e "	混淆参数 : $green$acc_obfs_param$plain" && echo "$separator"
}

SetAccSpeedCon(){
	echo -e "请输入要设置的用户 单线程 限速上限(单位：KB/S)"
	echo -e "$tip 单线程限速：每个端口 单线程的限速上限，多线程即无效。"
	while read -p "(默认: 无限):" acc_speed_con; do
        case "$acc_speed_con" in
            ("")
                break
            ;;
           (*[!0-9]*)
                echo -e "$error 请输入正确的数字(1-131072) "
            ;;
            (*)
                if [ "$acc_speed_con" -ge 1 ] && [ "$acc_speed_con" -le 131072 ]; then
                    break
                else
                    echo -e "$error 请输入正确的数字(1-131072)"
                fi
            ;;
        esac
	done
    if [ -z "$acc_speed_con" ]; then
		acc_speed_con_text="无限"
	else
		acc_speed_con_byte=$(numfmt --from=iec "$acc_speed_con"K)
		acc_speed_con_text=$(numfmt --to=iec --suffix=B "$acc_speed_con_byte")"/s"
	fi
    echo && echo "$separator" && echo -e "	单线程限速 : $green$acc_speed_con_text$plain" && echo "$separator" && echo
}

SetAccSpeedUser(){
	echo -e "请输入要设置的用户 总速度 限速上限(单位：KB/S)"
	echo -e "$tip 端口总限速：每个端口 总速度 限速上限，单个端口整体限速。"
	while read -p "(默认: 无限):" acc_speed_user; do
        case "$acc_speed_user" in
            ("")
                break
            ;;
           (*[!0-9]*)
                echo -e "$error 请输入正确的数字(1-131072) "
            ;;
            (*)
                if [ "$acc_speed_user" -ge 1 ] && [ "$acc_speed_user" -le 131072 ]; then
                    break
                else
                    echo -e "$error 请输入正确的数字(1-131072)"
                fi
            ;;
        esac
	done
    if [ -z "$acc_speed_user" ]; then
		acc_speed_user_text="无限"
	else
		acc_speed_user_byte=$(numfmt --from=iec "$acc_speed_user"K)
		acc_speed_user_text=$(numfmt --to=iec --suffix=B "$acc_speed_user_byte")"/s"
	fi
    echo && echo "$separator" && echo -e "	用户总限速 : $green$acc_speed_user_text$plain" && echo "$separator" && echo
}

SetAccTransfer(){
	echo -e "请输入要设置的用户 可使用的总流量上限(单位: GB, 1-838868 GB)"
	while read -p "(默认: 1000G):" acc_transfer; do
        case "$acc_transfer" in
            ("")
                acc_transfer="1000" && echo && break
            ;;
           (*[!0-9]*)
                echo -e "$error 请输入正确的数字(1-838868) "
            ;;
            (*)
                if [ "$acc_transfer" -ge 1 ] && [ "$acc_transfer" -le 838868 ]; then
                    break
                else
                    echo -e "$error 请输入正确的数字(1-838868)"
                fi
            ;;
        esac
	done
    if [ "$acc_transfer" == "838868" ]; then
		acc_transfer_text="无限"
	else
		acc_transfer_enable=$(numfmt --from=iec "$acc_d_byte"G)
		acc_transfer_text=$(numfmt --to=iec "$acc_transfer_enable")
	fi
    echo && echo "$separator" && echo -e "	用户总限速 : $green$acc_transfer_text$plain" && echo "$separator" && echo
}

SetAccForbid(){
	echo "请输入要设置的用户 禁止访问的端口"
	echo -e "$tip 禁止的端口：例如不允许访问 25端口，用户就无法通过SSR代理访问 邮件端口25了，如果禁止了 80,443 那么用户将无法正常访问 http/https 网站。
封禁单个端口格式: 25
封禁多个端口格式: 23,465
封禁  端口段格式: 233-266
封禁多种格式端口: 25,465,233-666 (不带冒号:)"
	read -p "(默认为空 不禁止访问任何端口):" forbid
	[ -z "$forbid" ] && forbid_text="无" || forbid_text="$forbid"
	echo && echo "$separator" && echo -e "	禁止的端口 : $green$forbid_text$plain" && echo "$separator" && echo
}

AddIptables(){
	if firewall-cmd -h > /dev/null 2>&1; then #centos 7
		default_zone=$(firewall-cmd --get-default-zone)
		firewall-cmd --permanent --zone="$default_zone" --add-port="$acc_port/tcp"
		firewall-cmd --permanent --zone="$default_zone" --add-port="$acc_port/udp"
		if systemctl status firewalld > /dev/null 2>&1; then #running
			firewall-cmd --reload
		fi
	elif iptables -h > /dev/null 2>&1; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport "$acc_port" -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport "$acc_port" -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport "$acc_port" -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport "$acc_port" -j ACCEPT
		if [ "$release" == "rpm" ]; then
            /etc/init.d/iptables save
            /etc/init.d/iptables restart
		else
			iptables-save > /etc/iptables.up.rules
			ip6tables-save > /etc/ip6tables.up.rules
			echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
			chmod +x /etc/network/if-pre-up.d/iptables
		fi
	else
		echo -e "$error 设置防火墙失败！请检查！" && exit 1
	fi
	echo -e "$info 防火墙设置成功！" && echo
}

DelIptables(){
	if firewall-cmd -h > /dev/null 2>&1; then #centos 7
		default_zone=$(firewall-cmd --get-default-zone)
		firewall-cmd --permanent --zone="$default_zone" --remove-port="$acc_port/tcp"
		firewall-cmd --permanent --zone="$default_zone" --remove-port="$acc_port/udp"
		if systemctl status firewalld > /dev/null 2>&1; then #running
			firewall-cmd --reload
		fi
	elif iptables -h > /dev/null 2>&1; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport "$acc_port" -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport "$acc_port" -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport "$acc_port" -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport "$acc_port" -j ACCEPT
		if [ "$release" == "rpm" ]; then
            /etc/init.d/iptables save
            /etc/init.d/iptables restart
		else
			iptables-save > /etc/iptables.up.rules
			ip6tables-save > /etc/ip6tables.up.rules
			#rm /etc/network/if-pre-up.d/iptables
		fi
	fi
}

GetAccsInfo(){
	accs_count=$($JQ_FILE -r '. | length' $MUDB_FILE)
	[ "$accs_count" == 0 ] && echo -e "$error 没有发现 用户，请检查 !" && exit 1
	IFS=" " read -a accs_d <<< "$($JQ_FILE -r '[.[].d] | @sh' $MUDB_FILE)"
	# OR accs_d=($($JQ_FILE -r '[.[].d] | @sh' $MUDB_FILE))
	#IFS=" " read -a accs_enable <<< "$($JQ_FILE -r '[.[].enable] | @sh' $MUDB_FILE)"
	#IFS=" " read -a accs_forbidden_port <<< "$($JQ_FILE -r '[.[].forbidden_port] | @sh' $MUDB_FILE)"
	#IFS=" " read -a accs_method <<< "$($JQ_FILE -r '[.[].method] | @sh' $MUDB_FILE)"
	#IFS=" " read -a accs_obfs <<< "$($JQ_FILE -r '[.[].obfs] | @sh' $MUDB_FILE)"
	#IFS=" " read -a accs_obfs_param <<< "$($JQ_FILE -r '[.[].obfs_param] | @sh' $MUDB_FILE)"
	#IFS=" " read -a accs_passwd <<< "$($JQ_FILE -r '[.[].passwd] | @sh' $MUDB_FILE)"
	IFS=" " read -a accs_port <<< "$($JQ_FILE -r '[.[].port] | @sh' $MUDB_FILE)"
	#IFS=" " read -a accs_protocol <<< "$($JQ_FILE -r '[.[].protocol] | @sh' $MUDB_FILE)"
	#IFS=" " read -a accs_protocol_param <<< "$($JQ_FILE -r '[.[].protocol_param] | @sh' $MUDB_FILE)"
	#IFS=" " read -a accs_speed_con <<< "$($JQ_FILE -r '[.[].speed_limit_per_con] | @sh' $MUDB_FILE)"
	#IFS=" " read -a accs_speed_user <<< "$($JQ_FILE -r '[.[].speed_limit_per_user] | @sh' $MUDB_FILE)"
	IFS=" " read -a accs_transfer_enable <<< "$($JQ_FILE -r '[.[].transfer_enable] | @sh' $MUDB_FILE)"
	IFS=" " read -a accs_u <<< "$($JQ_FILE -r '[.[].u] | @sh' $MUDB_FILE)"
	IFS=" " read -a accs_user <<< "$($JQ_FILE -r '[.[].user] | @sh' $MUDB_FILE)"
}

#BytesToHuman() {
#    b=${1:-0}; d=''; s=0; S=(Bytes {K,M,G,T,P,E,Z,Y}B)
#    while ((b > 1024)); do
#        d="$(printf ".%02d" $((b % 1024 * 100 / 1024)))"
#        b=$((b / 1024))
#        let s++
#    done
#    echo "$b$d ${S[$s]}"
#}

ListAccs(){
	GetAccsInfo
	accs_list=""
	accs_transfer_used=0
	for((index = 0; index < "$accs_count"; index++)); do
		acc_transfer_used=$(((accs_d[index]+accs_u[index])*1024))
		acc_transfer_used_text=$(numfmt --to=iec --suffix=B "$acc_transfer_used")
		acc_transfer_left=$((accs_transfer_enable[index]-acc_transfer_used))
		acc_transfer_left_text=$(numfmt --to=iec --suffix=B "$acc_transfer_left")
		accs_transfer_used=$((acc_transfer_used+accs_transfer_used))
		acc_transfer_enable_text=$(numfmt --to=iec --suffix=B "${accs_transfer_enable[index]}")
		accs_list=$accs_list"#$((index+1)) 用户名: $green${accs_user[index]}$plain\t 端口: $green${accs_port[index]}$plain\t 流量使用情况(已用+剩余=总): $green$acc_transfer_used_text$plain + $green$acc_transfer_left_text$plain = $green$acc_transfer_enable_text$plain\n"
	done
	accs_transfer_used_text=$(numfmt --to=iec --suffix=B "$accs_transfer_used")
	echo && echo -e "=== 用户总数 $green_background $accs_count $plain"
	echo -e "$accs_list"
	echo -e "=== 当前所有用户已使用流量总和: $green_background $accs_transfer_used_text $plain\n"
}

GetAccInfo(){
	acc_info_array=()
	while IFS='' read -r acc_line; do
		acc_info_array+=("$acc_line");
	done < <($JQ_FILE -r '.[] | select(.port=='"$acc_port"') | .[] | @sh' $MUDB_FILE)
	read acc_d acc_enable acc_forbidden_port acc_method acc_obfs acc_obfs_param acc_passwd acc_port acc_protocol acc_protocol_param acc_speed_con acc_speed_user acc_transfer_enable acc_u acc_user <<< "${acc_info_array[@]}"
	acc_forbidden_port=${acc_forbidden_port//\'/}
	acc_method=${acc_method//\'/}
	acc_obfs=${acc_obfs//\'/}
	acc_obfs_param=${acc_obfs_param//\'/}
	acc_passwd=${acc_passwd//\'/}
	acc_protocol=${acc_protocol//\'/}
	acc_protocol_param=${acc_protocol_param//\'/}
	acc_user=${acc_user//\'/}
	acc_transfer_used=$(((acc_d+accs_u)*1024))
	acc_transfer_left=$((acc_transfer_enable-acc_transfer_used))
	acc_d_byte=$((acc_d*1024))
	acc_u_byte=$((acc_u*1024))
	acc_d_text=$(numfmt --to=iec --suffix=B "$acc_d_byte")
	acc_u_text=$(numfmt --to=iec --suffix=B "$acc_u_byte")
}

ViewAccInfo(){
	[ -z "$server_name" ] && server_name=$(< "$USER_API_CONFIG_FILE" grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	clear && echo "===================================================" && echo
	echo -e " 用户 [$acc_user] 的配置信息：" && echo
	echo -e " 地址\t    : $green$server_name$plain"
	echo -e " 端口\t    : $green$acc_port$plain"
	echo -e " 密码\t    : $green$acc_passwd$plain"
	echo -e " 加密\t    : $green$acc_method$plain"
	echo -e " 协议\t    : $red$acc_protocol$plain"
	echo -e " 混淆\t    : $red$acc_obfs$plain"
	echo -e " 混淆的参数 : $green$acc_obfs_param$plain"
	echo -e " 设备数限制 : $green$acc_protocol_param$plain"
	echo -e " 单线程限速 : $green$acc_speed_con_text$plain"
	echo -e " 用户总限速 : $green$acc_speed_user_text$plain"
	echo -e " 禁止的端口 : $green$acc_port$plain"
	echo
	echo -e " 已使用流量 : 上传: $green$acc_u_text$plain + 下载: $green$acc_d_text$plain = $green$acc_transfer_used_text$plain"
	echo -e " 剩余的流量 : $green$acc_transfer_left_text$plain"
	echo -e " 用户总流量 : $green$acc_transfer_enable_text$plain"
	echo -e "$ss_link"
	echo -e "$ssr_link"
	echo
}

AddAcc(){
	SetAccUser
	SetAccPort
	SetAccPasswd
	SetAccMethod
	SetAccProtocol
	SetAccProtocolParam
	SetAccObfs
	SetAccObfsParam
	SetAccSpeedCon
	SetAccSpeedUser
	SetAccTransfer
	SetAccForbid
    [ -n "$acc_speed_con" ] && limit_option="-s $acc_speed_con"
    [ -n "$acc_speed_user" ] && limit_option="$limit_option -S $acc_speed_user"
    [ -n "$acc_forbidden_port" ] && limit_option="$limit_option -f $acc_forbidden_port"
	cd "$SSR_PATH"
	if python mujson_mgr.py -a -u "$acc_user" -p "$acc_port" -k "$acc_passwd" -m "$acc_method" -O "$acc_protocol" -G "$acc_protocol_param" -o "$acc_obfs" -g "$acc_obfs_param" -t "$acc_transfer" "$limit_option"|grep -q "add user info"; then
		echo -e "$info 用户添加成功! " && echo
	else
		echo -e "$error 用户添加失败 ${green}[用户名: $acc_user , 端口: $acc_port]$plain "
		exit 1
	fi
	AddIptables
	SsSsrLink
	ViewAccInfo
}

AddAccAgain(){
	while read -p "是否继续 添加用户配置？[Y/n 默认否]:" add_again_yn; do
		[ -z "$add_again_yn" ] && add_again_yn="n"
		if [[ "$add_again_yn" == [Nn] ]]; then
			break
		else
			echo -e "$info 继续 添加用户配置..."
			AddAcc
		fi
	done
}

SsSsrLink(){
	ss_link=""
	if [ "$acc_protocol" == "origin" ] || [ "$acc_protocol" == "auth_sha1_v4_compatible" ]; then
		if [ "$acc_obfs" == "plain" ] || echo "$acc_obfs" | grep -q "_compatible"; then
			ss_url="ss://"$(echo -n "$acc_method:$acc_passwd@$server_name:$acc_port"|base64 -w0 |sed 's/=//g;s/\//_/g;s/+/-/g')
			ss_link=" SS    链接 : $green$ss_url$plain"
		fi
	fi
	acc_passwd_base64=$(echo -n "$acc_passwd"|base64 -w0 |sed 's/=//g;s/\//_/g;s/+/-/g')
	acc_protocol_param_base64=$(echo -n "$acc_protocol_param"|base64 -w0 |sed 's/=//g;s/\//_/g;s/+/-/g')
	acc_obfs_param_base64=$(echo -n "$acc_obfs_param"|base64 -w0 |sed 's/=//g;s/\//_/g;s/+/-/g')
	ssr_url="ssr://"$(echo -n "$server_name:$acc_port:${acc_protocol//_compatible/}:$acc_method:${acc_obfs//_compatible/}:$acc_passwd_base64/?obfsparam=$acc_obfs_param_base64&protoparam=$acc_protocol_param_base64"|base64 -w0 |sed 's/=//g;s/\//_/g;s/+/-/g')
	ssr_link=" SSR   链接 : $red$ssr_url$plain"
}

DownInit(){
	if [ -d "$SSR_PATH" ]; then
		if [ ! -e "/etc/init.d/ssrmu" ]; then
			echo -e "$info 正在下载 ssrmu.init..."
			wget --no-check-certificate https://raw.githubusercontent.com/woniuzfb/doubi/master/ssrmu.init -qO /etc/init.d/ssrmu
			chmod +x /etc/init.d/ssrmu
		fi
	else
		echo -e "$error ShadowsocksR不存在，请先安装！" && echo && exit 1
	fi
}

StartSsr(){
	DownInit
	/etc/init.d/ssrmu start
}

StopSsr(){
	DownInit
	/etc/init.d/ssrmu stop
}

RestartSsr(){
	DownInit
	/etc/init.d/ssrmu restart
}

InstallSsrMenu(){
	[ -d "$SSR_PATH" ] && echo -e "$error ShadowsocksR 文件夹已存在，请检查( 如安装失败或者存在旧版本，请先卸载 ) !" && exit 1
	echo -e "$info 开始安装/配置 ShadowsocksR依赖..."
	CheckRelease
	ChangeDate
	RestartCron
	InstallSsr
	InstallJq
	SetServerName
	echo -e "$info 开始设置 ShadowsocksR账号配置..."
	AddAcc
	AddAccAgain
	echo -e "$info 所有步骤 安装完毕，开始启动 ShadowsocksR服务端..."
	StartSsr
}

ViewAccMenu(){
	ListAccs
	echo -e "请输入要查看的账号端口 "
	while read -p "(默认: 取消):" acc_port; do
		case "$acc_port" in
			("")
				echo "已取消..." && exit 1
			;;
			(*[!0-9]*)
				echo -e "$error 请输入正确的数字！"
			;;
			(*)
				if [ -n "$($JQ_FILE '.[] | select(.port=='"$acc_port"')' $MUDB_FILE)" ]; then
					break;
				else
					echo -e "$error 账号不存在！"
				fi
			;;
		esac
	done
	GetAccInfo
	SsSsrLink
	ViewAccInfo
}

InstallLibsodium(){
	CheckRelease
	if [ -e "/usr/local/lib/libsodium.so" ] || [ -e "/usr/lib/libsodium.so" ]; then
		echo -e "$error libsodium 已安装 , 是否覆盖安装(更新)？[Y/n]"
		read -e -p "(默认: n):" libso_yn
		[ -z "$libso_yn" ] && libso_yn="n"
		[[ "$libso_yn" == [Nn] ]] && echo "已取消..." && exit 1
	else
		echo -e "$info libsodium 未安装，开始安装..."
	fi
	echo -e "$info 开始获取 libsodium 最新版本..."
	#experimental# grep -Po '"tag_name": "\K.*?(?=")'
	libso_ver=$(curl --silent "https://api.github.com/repos/jedisct1/libsodium/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)
	[ -z "$libso_ver" ] && libso_ver=$libso_ver_default
	echo -e "$info libsodium 最新版本为 $green$libso_ver$plain !"
	if [ "$release" == "rpm" ]; then
		yum -y update
		echo -e "$info 安装依赖..."
		yum -y groupinstall "Development Tools"
		echo -e "$info 下载..."
		wget --no-check-certificate "https://github.com/jedisct1/libsodium/releases/download/$libso_ver/libsodium-$libso_ver.tar.gz" -qO "libsodium-$libso_ver.tar.gz"
		echo -e "$info 解压..."
		tar -xzf libsodium-$libso_ver.tar.gz && cd libsodium-"$libso_ver"
		echo -e "$info 编译安装..."
		./configure && make && make install
	else
		apt-get -y update
		echo -e "$info 安装依赖..."
		apt-get -y install build-essential
		echo -e "$info 下载..."
		wget --no-check-certificate "https://github.com/jedisct1/libsodium/releases/download/$libso_ver/libsodium-$libso_ver.tar.gz" -qO "libsodium-$libso_ver.tar.gz"
		echo -e "$info 解压..."
		tar -xzf libsodium-$libso_ver.tar.gz && cd libsodium-$libso_ver
		echo -e "$info 编译安装..."
		./configure && make && make install
	fi
    if ! ldconfig -p | grep -q "/usr/local/lib"; then
        echo "/usr/local/lib" > /etc/ld.so.conf.d/usr_local_lib.conf
    fi
	ldconfig
	cd .. && rm -rf libsodium-$libso_ver.tar.gz && rm -rf libsodium-$libso_ver
	[ ! -e "/usr/local/lib/libsodium.so" ] && echo -e "$error libsodium 安装失败 !" && exit 1
	echo && echo -e "$info libsodium 安装成功 !" && echo
}

ViewConnection(){
	CheckRelease
	echo && echo -e "请选择要显示的格式：
 ${green}1.$plain 显示 IP 格式
 ${green}2.$plain 显示 IP+IP归属地 格式" && echo
	read -p "(默认: 1):" view_con_num
	[ -z "$view_con_num" ] && view_con_num="1"
	if [ "$view_con_num" != "1" ] && [ "$view_con_num" != "2" ]; then
		echo -e "$error 请输入正确的数字(1-2)" && exit 1
	else
		GetAccsInfo
		accs_list=""
		acc_ip_count=0
		for((index=0;index<accs_count;index++)); do
			acc_user="${accs_port[index]}"
			acc_port="${accs_port[index]}"
			acc_ip=$(ss -taH state established '( sport = :'"$acc_port"' )' |awk '{print $4}'|grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"|sort -u|grep -v 'Segmentation fault' || true)
			if [ "$view_con_num" == "2" ]; then
				acc_ip_new=""
				echo -e "$tip 检测IP归属地(ipip.net)，如果IP较多，可能时间会比较长..."
				IFS=' ' read -a acc_ip_array <<< "$acc_ip"
				for one_ip in "${acc_ip_array[@]}"; do
					one_ip_info=$(wget -qO- -t1 -T2 http://freeapi.ipip.net/"$one_ip"|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g')
					acc_ip_new="$acc_ip_new$one_ip($one_ip_info) "
				done
				acc_ip=$acc_ip_new
			fi
			acc_ip_count=$(echo "$acc_ip"|wc -w)
			accs_ip_count=$((accs_ip_count+acc_ip_count))
			accs_list=${accs_list}"#$((index+1)) 用户名: $green$acc_user$plain\t 端口: $green$acc_port$plain\t 链接IP总数: $green$acc_ip_count$plain\t 当前链接IP: $green$acc_ip$plain\n"
		done
		echo -e "用户总数: $green_background $accs_count $plain 链接IP总数: $green_background $accs_ip_count $plain "
		echo -e "$accs_list"
	fi
}

ReadAccPort(){
	echo -e "请输入用户 端口"
	while read -p "(默认: 取消):" acc_port; do
		[ -z "$acc_port" ] && echo -e "已取消..." && exit 1
		if [ -n "$($JQ_FILE '.[] | select(.port=='"$acc_port"')' $MUDB_FILE)" ]; then
			break
		else
			echo -e "$error 请输入正确的端口 !"
		fi
	done
}

ConfigAccDel(){
	if python mujson_mgr.py -d -p "$acc_port"|grep -q "delete user "; then
		DelIptables
		echo -e "$info 用户删除成功 ${green}[端口: $acc_port]$plain "
	else
		echo -e "$error 用户删除失败 ${green}[端口: $acc_port]$plain "
	fi
}

ConfigAccPasswd(){
	if python mujson_mgr.py -e -p "$acc_port" -k "$acc_passwd"|grep -q "edit user "; then
		echo -e "$info 用户密码修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户密码修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccMethod(){
	if python mujson_mgr.py -e -p "$acc_port" -m "$acc_method"|grep -q "edit user "; then
		echo -e "$info 用户加密方式修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户加密方式修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccProtocol(){
	if python mujson_mgr.py -e -p "$acc_port" -O "$acc_protocol"|grep -q "edit user "; then
		echo -e "$info 用户协议修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户协议修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccObfs(){
	if python mujson_mgr.py -e -p "$acc_port" -o "$acc_obfs"|grep -q "edit user "; then
		echo -e "$info 用户混淆修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户混淆修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccObfsParam(){
	if python mujson_mgr.py -e -p "$acc_port" -g "$acc_obfs_param"|grep -q "edit user "; then
		echo -e "$info 用户混淆参数修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户混淆参数修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccProtocolParam(){
	if python mujson_mgr.py -e -p "$acc_port" -G "$acc_protocol_param"|grep -q "edit user "; then
		echo -e "$info 用户议参数(设备数限制)修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户协议参数(设备数限制)修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccSpeedCon(){
	if python mujson_mgr.py -e -p "$acc_port" -s "$acc_speed_con"|grep -q "edit user "; then
		echo -e "$info 用户单线程限速修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户单线程限速修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccSpeedUser(){
	if python mujson_mgr.py -e -p "$acc_port" -S "$acc_speed_user"|grep -q "edit user "; then
		echo -e "$info 用户端口总限速修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户端口总限速修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccTransfer(){
	if python mujson_mgr.py -e -p "$acc_port" -t "$acc_transfer"|grep -q "edit user "; then
		echo -e "$info 用户总流量修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户总流量修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccForbid(){
	if python mujson_mgr.py -e -p "$acc_port" -f "$acc_forbidden_port"|grep -q "edit user "; then
		echo -e "$info 用户禁止访问端口修改成功 ${green}[端口: $acc_port]$plain (注意：可能需要十秒左右才会应用最新配置)"
	else
		echo -e "$error 用户禁止访问端口修改失败 ${green}[端口: $acc_port]$plain " && exit 1
	fi
}

ConfigAccStatus(){
	case $acc_enable in
		1)
			acc_status_old="启用"
			acc_status_new="禁用"
			acc_u_new=$acc_u
			acc_d_new=$acc_d
			if [ $acc_transfer_left -gt 0 ]; then
				acc_enable_new=$((acc_transfer_left+1))
			else
				acc_enable_new=0
			fi
		;;
		0)
			acc_status_old="禁用"
			acc_status_new="启用"
			acc_enable_new=1
			acc_u_new=0
			acc_d_new=0
		;;
		*)
			acc_status_old="禁用"
			acc_status_new="启用"
			acc_enable_new=1
		;;
	esac

	echo -e "端口 [$acc_port] 的账号状态为：$green$acc_status_old$plain , 是否切换为 $red$acc_status_new$plain ?[Y/n]"
	read -p "(默认: Y):" acc_status_num
	[ -z "$acc_status_num" ] && acc_status_num="Y"
	if [[ "$acc_status_num" == [Yy] ]]; then
		case $acc_enable in
			1) echo
			;;
			0) echo && SetAccTransfer
			;;
			*)
				echo && echo -e "你要做什么？
${green}1.$plain  恢复账号原先的流量使用状态
${green}2.$plain  重新设置账号流量"
				read -p "(默认: 取消):" acc_status_recov
				[ -z "$acc_status_recov" ] && acc_status_recov=1
				case $acc_status_recov in
					1)
						acc_u_new=$acc_u
						acc_d_new=$acc_d
						acc_transfer_enable=$((acc_enable-1))
					;;
					2)
						acc_u_new=0
						acc_d_new=0
						SetAccTransfer
					;;
					*) echo "已取消..." && exit 1
					;;
				esac
			;;
		esac
		$JQ_FILE '(.[]|select(.port=='"$acc_port"')|.enable)='"$acc_enable_new"'|(.[]|select(.port=='"$acc_port"')|.u)='"$acc_u_new"'|(.[]|select(.port=='"$acc_port"')|.d)='"$acc_d_new"'|(.[]|select(.port=='"$acc_port"')|.transfer_enable)='"$acc_transfer_enable"'' "$MUDB_FILE" > mudb.tmp
		mv mudb.tmp "$MUDB_FILE"
	else
		echo "已取消..." && exit 1
	fi
	echo && echo "操作成功..."
	SsSsrLink
	ViewAccInfo
}

ConfigAccAll(){
	SetAccPasswd
	SetAccMethod
	SetAccProtocol
	SetAccObfs
	SetAccObfsParam
	SetAccProtocolParam
	SetAccSpeedCon
	SetAccSpeedUser
	SetAccTransfer
	SetAccForbid
	SetAccUser
	SetAccPort
	ConfigAccPasswd
	ConfigAccMethod
	ConfigAccProtocol
	ConfigAccObfs
	ConfigAccObfsParam
	ConfigAccProtocolParam
	ConfigAccSpeedCon
	ConfigAccSpeedUser
	ConfigAccTransfer
	ConfigAccForbid
	ConfigAccUser
	ConfigAccPort
}

ConfigServerName(){
	server_pub_addr=$(< $USER_API_CONFIG_FILE grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	if [ -z "$server_pub_addr" ]; then
		echo -e "$error 获取当前配置的 服务器IP或域名失败！" && exit 1
	else
		echo -e "$info 当前配置的服务器IP或域名为： $green$server_pub_addr$plain"
	fi
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${server_name}'/" "$USER_API_CONFIG_FILE"
	echo && echo -e "修改成功	IP/域名: $red_background $server_name $plain" && echo
}

ConfigAccMenu(){
	echo && echo -e "你要做什么？
  ${green}1.$plain 添加 用户账号
  ${green}2.$plain 删除 用户账号
  ${green}3.$plain 禁用/启用账号
————— 修改 用户账号 —————
  ${green}4.$plain 修改 用户密码
  ${green}5.$plain 修改 加密方式
  ${green}6.$plain 修改 协议插件
  ${green}7.$plain 修改 混淆插件
  ${green}8.$plain 修改 混淆参数
  ${green}9.$plain 修改 设备数限制
 ${green}10.$plain 修改 单线程限速
 ${green}11.$plain 修改 用户总限速
 ${green}12.$plain 修改 用户总流量
 ${green}13.$plain 修改 用户禁用端口
 ${green}14.$plain 修改 用户名
 ${green}15.$plain 修改 用户端口
 ${green}16.$plain 修改 全部配置
————— 其他 —————
 ${green}17.$plain 修改 服务器名称(IP或域名)
 
 $tip 修改用户账号后稍等片刻即可生效 !" && echo
	read -p "(默认: 取消):" config_acc_num
	[ -z "$config_acc_num" ] && echo "已取消..." && exit 1
	cd "$SSR_PATH"
	case $config_acc_num in
		1) AddAcc && AddAccAgain
		;;
		2) ReadAccPort && ConfigAccDel
		;;
		3) ReadAccPort && GetAccInfo && ConfigAccStatus
		;;
		4) ReadAccPort && SetAccPasswd && ConfigAccPasswd
		;;
		5) ReadAccPort && SetAccMethod && ConfigAccMethod
		;;
		6) ReadAccPort && SetAccProtocol && ConfigAccProtocol
		;;
		7) ReadAccPort && SetAccObfs && ConfigAccObfs
		;;
		8) ReadAccPort && SetAccObfsParam && ConfigAccObfsParam
		;;
		9) ReadAccPort && SetAccProtocolParam && ConfigAccProtocolParam
		;;
		10) ReadAccPort && SetAccSpeedCon && ConfigAccSpeedCon
		;;
		11) ReadAccPort && SetAccSpeedUser && ConfigAccSpeedUser
		;;
		12) ReadAccPort && SetAccTransfer && ConfigAccTransfer
		;;
		13) ReadAccPort && SetAccForbid && ConfigAccForbid
		;;
		14) ReadAccPort && SetAccUser && ConfigAccUser
		;;
		15) ReadAccPort && SetAccPort && ConfigAccPort
		;;
		16) ReadAccPort && ConfigAccAll
		;;
		17) ReadAccPort && SetServerName && ConfigServerName
		;;
	esac
}

ConfigAccDiy(){
	vi "$MUDB_FILE"
	echo "是否现在重启ShadowsocksR？[Y/n]" && echo
	read -p "(默认: y):" acc_diy_yn
	[ -z "$acc_diy_yn" ] && acc_diy_yn="y"
	[[ "$acc_diy_yn" == [Yy] ]] && RestartSsr
}

ClearTransferSetCron(){
	echo -e "请输入流量清零时间间隔
 === 格式说明 ===
 * * * * * 分别对应 分钟 小时 日份 月份 星期
 ${green} 0 2 1 * * $plain 代表 每月1日2点0分 清零已使用流量
 ${green} 0 2 15 * * $plain 代表 每月15日2点0分 清零已使用流量
 ${green} 0 2 */7 * * $plain 代表 每7天2点0分 清零已使用流量
 ${green} 0 2 * * 0 $plain 代表 每个星期日(7) 清零已使用流量
 ${green} 0 2 * * 3 $plain 代表 每个星期三(3) 清零已使用流量" && echo
	read -e -p "(默认: 0 2 1 * * 每月1日2点0分):" crontab_f
	[ -z "$crontab_f" ] && crontab_f="0 2 1 * *"
}

ClearTransferOne(){
	List_port_user
	ReadAccPort
	cd "$SSR_PATH"
	if python mujson_mgr.py -c -p "$acc_port"|grep -q "clear user "; then
		echo -e "$error 用户已使用流量清零失败 ${green}[端口: $acc_port]$plain "
	else
		echo -e "$info 用户已使用流量清零成功 ${green}[端口: $acc_port]$plain "
	fi
}

ClearTransferAll(){
	GetAccsInfo
	cd "$SSR_PATH"
	for acc_port in "${accs_port[@]}"; do
		if python mujson_mgr.py -c -p "$acc_port"|grep -q "clear user "; then
			echo -e "$info 用户流量清零成功 ${green}[端口: $acc_port]$plain "
		else
			echo -e "$error 用户流量清零失败 ${green}[端口: $acc_port]$plain "
		fi
	done
	echo -e "$info 所有用户流量清零完毕 !"
}

ClearTransferAllCronStart(){
	crontab -l > "$HOME/crontab.bak"
	sed -i "/ssrmu.sh/d" "$HOME/crontab.bak"
	echo -e "\n$crontab_f /bin/bash $HOME/ssrmu.sh clearall" >> "$HOME/crontab.bak"
	crontab "$HOME/crontab.bak"
	rm -r "$HOME/crontab.bak"
	if crontab -l | grep -q "ssrmu.sh"; then
		echo -e "$info 定时所有用户流量清零启动成功 !"
	else
		echo -e "$error 定时所有用户流量清零启动失败 !" && exit 1
	fi
}

ClearTransferAllCronStop(){
	crontab -l > "$HOME/crontab.bak"
	sed -i "/ssrmu.sh/d" "$HOME/crontab.bak"
	crontab "$HOME/crontab.bak"
	rm -r "$HOME/crontab.bak"
	if crontab -l | grep -q "ssrmu.sh"; then
		echo -e "$info 定时所有用户流量清零停止成功 !"
	else
		echo -e "$error 定时所有用户流量清零停止失败 !" && exit 1
	fi
}

ClearTransferAllCronModify(){
	ClearTransferSetCron
	ClearTransferAllCronStop
	ClearTransferAllCronStart
}

ClearTransferMenu(){
	echo && echo -e "你要做什么？
 ${green}1.$plain  清零 单个用户已使用流量
 ${green}2.$plain  清零 所有用户已使用流量(不可挽回)
 ${green}3.$plain  启动 定时所有用户流量清零
 ${green}4.$plain  停止 定时所有用户流量清零
 ${green}5.$plain  修改 定时所有用户流量清零" && echo
	read -p "(默认: 取消):" transfer_num
	[ -z "$transfer_num" ] && echo "已取消..." && exit 1
	case $transfer_num in
		1) ClearTransferOne
		;;
		2)
			echo "确定要 清零 所有用户已使用流量？[Y/n]" && echo
			read -e -p "(默认: n):" clear_transfer_all_num
			[ -z "$clear_transfer_all_num" ] && clear_transfer_all_num="n"
			if [[ ${clear_transfer_all_num} == [Yy] ]]; then
				ClearTransferAll
			else
				echo "已取消..."
			fi
		;;
		3)
			ClearTransferSetCron
			ClearTransferAllCronStart
		;;
		4)
			ClearTransferAllCronStop
		;;
		5)
			ClearTransferAllCronModify
		;;
		*) echo -e "$error 请输入正确的数字(1-5)" && exit 1
		;;
	esac
}

ConfigBbr(){
	if [ ! -e "$BBR_FILE" ]; then
		echo -e "$error 没有发现 BBR脚本，开始下载..."
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/bbr.sh -qO "$BBR_FILE"; then
			echo -e "$error BBR 脚本下载失败 !" && exit 1
		else
			echo -e "$info BBR 脚本下载完成 !"
			chmod +x bbr.sh
		fi
	fi
	echo && echo -e "  你要做什么？

 ${green}1.$plain 安装 BBR
————————
 ${green}2.$plain 启动 BBR
 ${green}3.$plain 停止 BBR
 ${green}4.$plain 查看 BBR 状态" && echo
echo -e "${green} [安装前 请注意] $plain
1. 安装开启BBR，需要更换内核，存在更换失败等风险(重启后无法开机)
2. 本脚本仅支持 Debian / Ubuntu 系统更换内核，OpenVZ和Docker 不支持更换内核
3. Debian 更换内核过程中会提示 [ 是否终止卸载内核 ] ，请选择 $green NO $plain" && echo
	read -p "(默认: 取消):" bbr_num
	[ -z "$bbr_num" ] && echo "已取消..." && exit 1
	case $bbr_num in
		1)
			[ "$release" = "rpm" ] && echo -e "$error 本脚本不支持 CentOS系统安装 BBR !" && exit 1
			bash "$BBR_FILE"
		;;
		2) bash "$BBR_FILE" start
		;;
		3) bash "$BBR_FILE" stop
		;;
		4) bash "$BBR_FILE" status
		;;
		*) echo -e "$error 请输入正确的数字(1-4)" && exit 1
		;;
	esac
}

InstallServerSpeeder(){
	[ -e "$SERVER_SPEEDER_FILE" ] && echo -e "$error 锐速(Server Speeder) 已安装 !" && exit 1
	wget --no-check-certificate https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder.sh -qO /tmp/serverspeeder.sh
	[ ! -e "/tmp/serverspeeder.sh" ] && echo -e "$error 锐速安装脚本下载失败 !" && exit 1
	bash /tmp/serverspeeder.sh
	sleep 2s
	PID=$(pgrep -f serverspeeder || true)
	if [ -n "$PID" ]; then
		rm -rf /tmp/serverspeeder.sh
		rm -rf /tmp/91yunserverspeeder
		rm -rf /tmp/91yunserverspeeder.tar.gz
		echo -e "$info 锐速(Server Speeder) 安装完成 !" && exit 1
	else
		echo -e "$error 锐速(Server Speeder) 安装失败 !" && exit 1
	fi
}

UninstallServerSpeeder(){
	[ ! -e "$SERVER_SPEEDER_FILE" ] && echo -e "$error 没有安装 锐速(Server Speeder)，请检查 !" && exit 1
	echo "确定要卸载 锐速(Server Speeder)？[y/N]" && echo
	read -p "(默认: n):" un_speeder_yn
	[ -z "$un_speeder_yn" ] && echo && echo "已取消..." && exit 1
	if [[ "$un_speeder_yn" == [Yy] ]]; then
		chattr -i /serverspeeder/etc/apx*
		bash "$SERVER_SPEEDER_FILE" uninstall -f
		echo && echo "锐速(Server Speeder) 卸载完成 !" && echo
	fi
}

ConfigServerSpeeder(){
	echo && echo -e "你要做什么？
 ${green}1.$plain 安装 锐速
 ${green}2.$plain 卸载 锐速
————————
 ${green}3.$plain 启动 锐速
 ${green}4.$plain 停止 锐速
 ${green}5.$plain 重启 锐速
 ${green}6.$plain 查看 锐速 状态
 
 注意： 锐速和LotServer不能同时安装/启动！" && echo
	read -p "(默认: 取消):" server_speeder_num
	[ -z "$server_speeder_num" ] && echo "已取消..." && exit 1
	case $server_speeder_num in
		1) InstallServerSpeeder
		;;
		2) UninstallServerSpeeder
		;;
		3) bash "$SERVER_SPEEDER_FILE" start && bash "$SERVER_SPEEDER_FILE" status
		;;
		4) bash "$SERVER_SPEEDER_FILE" stop
		;;
		5) bash "$SERVER_SPEEDER_FILE" restart && bash "$SERVER_SPEEDER_FILE" status
		;;
		6) bash "$SERVER_SPEEDER_FILE" status
		;;
		*) echo -e "$error 请输入正确的数字(1-6)" && exit 1
		;;
	esac
}

InstallLotServer(){
	[ -e "$LOTSERVER_FILE" ] && echo -e "$error LotServer 已安装 !" && exit 1
	wget --no-check-certificate "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh" -qO /tmp/appex.sh
	[ ! -e "/tmp/appex.sh" ] && echo -e "$error LotServer 安装脚本下载失败 !" && exit 1
	bash /tmp/appex.sh install
	sleep 2s
	PID=$(pgrep -f appex || true)
	if [ -n "$PID" ]; then
		echo -e "$info LotServer 安装完成 !" && exit 1
	else
		echo -e "$error LotServer 安装失败 !" && exit 1
	fi
}

UninstallLotServer(){
	[ ! -e "$LOTSERVER_FILE" ] && echo -e "$error 没有安装 LotServer，请检查 !" && exit 1
	echo "确定要卸载 LotServer？[y/N]" && echo
	read -p "(默认: n):" un_lot_yn
	[ -z "$un_lot_yn" ] && echo && echo "已取消..." && exit 1
	if [[ "$un_lot_yn" == [Yy] ]]; then
		wget --no-check-certificate "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh" -qO /tmp/appex.sh && bash /tmp/appex.sh uninstall
		echo && echo "LotServer 卸载完成 !" && echo
	fi
}

ConfigLotServer(){
	echo && echo -e "你要做什么？
 ${green}1.$plain 安装 LotServer
 ${green}2.$plain 卸载 LotServer
————————
 ${green}3.$plain 启动 LotServer
 ${green}4.$plain 停止 LotServer
 ${green}5.$plain 重启 LotServer
 ${green}6.$plain 查看 LotServer 状态
 
 注意： 锐速和LotServer不能同时安装/启动！" && echo
	read -p "(默认: 取消):" lotserver_num
	[ -z "$lotserver_num" ] && echo "已取消..." && exit 1
	case $lotserver_num in
		1) InstallLotServer
		;;
		2) UninstallLotServer
		;;
		3) bash "$LOTSERVER_FILE" start && bash "$LOTSERVER_FILE" status
		;;
		4) bash "$LOTSERVER_FILE" stop
		;;
		5) bash "$LOTSERVER_FILE" restart && bash "$LOTSERVER_FILE" status
		;;
		6) bash "$LOTSERVER_FILE" status
		;;
		*) echo -e "$error 请输入正确的数字(1-6)" && exit 1
		;;
	esac
}

BanBtPtSpam(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh banall
	rm -rf ban_iptables.sh
}

UnBanBtPtSpam(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh unbanall
	rm -rf ban_iptables.sh
}

ConfigVerboseLog(){
	connect_verbose_info=$($JQ_FILE '.connect_verbose_info' $USER_CONFIG_FILE)
	if [ "$connect_verbose_info" == "0" ]; then
		echo && echo -e "当前日志模式: $green简单模式（只输出错误日志）$plain" && echo
		echo -e "确定要切换为 $green详细模式（输出详细连接日志+错误日志）$plain？[Y/n]"
		read -e -p "(默认: n):" connect_verbose_info_ny
		[ -z "$connect_verbose_info_ny" ] && connect_verbose_info_ny="n"
		if [[ "$connect_verbose_info_ny" == [Yy] ]]; then
			connect_verbose_info="1"
		else
			echo && echo "	已取消..." && echo && exit 1
		fi
	else
		echo && echo -e "当前日志模式: $green详细模式（输出详细连接日志+错误日志）$plain" && echo
		echo -e "确定要切换为 $green简单模式（只输出错误日志）$plain？[y/N]"
		read -e -p "(默认: n):" connect_verbose_info_ny
		[ -z "$connect_verbose_info_ny" ] && connect_verbose_info_ny="n"
		if [[ "$connect_verbose_info_ny" == [Yy] ]]; then
			connect_verbose_info="0"
		else
			echo && echo "	已取消..." && echo && exit 1
		fi
	fi
	$JQ_FILE '.connect_verbose_info='"$connect_verbose_info"'' $USER_CONFIG_FILE > config.tmp
	mv config.tmp $USER_CONFIG_FILE
	RestartSsr
}

View_Log(){
	[ ! -e $SSR_LOG_FILE ] && echo -e "$error ShadowsocksR日志文件不存在 !" && exit 1
	echo && echo -e "$tip 按 ${red}Ctrl+C$plain 终止查看日志" && echo -e "如果需要查看完整日志内容，请用 ${red}cat $SSR_LOG_FILE$plain 命令。" && echo
	tail -f "$SSR_LOG_FILE"
}

OtherFunctions(){
	echo && echo -e "  你要做什么？
	
  ${green}1.$plain 配置 BBR
  ${green}2.$plain 配置 锐速(ServerSpeeder)
  ${green}3.$plain 配置 LotServer(锐速母公司)
  $tip 锐速/LotServer/BBR 不支持 OpenVZ！
  $tip 锐速和LotServer不能共存！
————————————
  ${green}4.$plain 一键封禁 BT/PT/SPAM (iptables)
  ${green}5.$plain 一键解封 BT/PT/SPAM (iptables)
————————————
  ${green}6.$plain 切换 ShadowsocksR日志输出模式
  —— 说明：SSR默认只输出错误日志，此项可切换为输出详细的访问日志。" && echo
	read -p "(默认: 取消):" other_num
	[ -z "$other_num" ] && echo "已取消..." && exit 1
	case "$other_num" in
		1) ConfigBbr
		;;
		2) ConfigServerSpeeder
		;;
		3) ConfigLotServer
		;;
		4) BanBtPtSpam
		;;
		5) UnBanBtPtSpam
		;;
		6) ConfigVerboseLog
		;;
		*) echo -e "$error 请输入正确的数字 [1-6]" && exit 1
		;;
	esac
}

UpdateScript(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/woniuzfb/doubi/master/ssrmu.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[ -z "$sh_new_ver" ] && echo -e "$error 无法链接到 Github !" && exit 1
	wget --no-check-certificate https://raw.githubusercontent.com/woniuzfb/doubi/master/ssrmu.init -qO /etc/init.d/ssrmu
	wget --no-check-certificate "https://raw.githubusercontent.com/woniuzfb/doubi/master/ssrmu.sh" -qO "$SH_FILE" && chmod +x "$SH_FILE"
	echo -e "脚本已更新为最新版本[ $sh_new_ver ] !(输入: ssr 使用)" && exit 0
}

Menu(){
	[ ! -e "$SH_FILE" ] && wget --no-check-certificate "https://raw.githubusercontent.com/woniuzfb/doubi/master/ssrmu.sh" -qO "$SH_FILE" && chmod +x "$SH_FILE"
	echo -e "  ShadowsocksR MuJSON一键管理脚本 ${red}[v$sh_ver]$plain
  ---- Toyo | Rewriting by MTimer ----

  ${green}1.$plain 安装 ShadowsocksR
  ${green}2.$plain 卸载 ShadowsocksR
  ${green}3.$plain 安装 libsodium
————————————
  ${green}4.$plain 查看 账号信息
  ${green}5.$plain 显示 连接信息
  ${green}6.$plain 设置 用户配置
  ${green}7.$plain 手动 修改配置
  ${green}8.$plain 配置 流量清零
————————————
  ${green}9.$plain 启动 ShadowsocksR
 ${green}10.$plain 停止 ShadowsocksR
 ${green}11.$plain 重启 ShadowsocksR
 ${green}12.$plain 查看 ShadowsocksR 日志
————————————
 ${green}13.$plain 其他功能
 ${green}14.$plain 升级脚本

 $tip 输入: ssr 打开此面板" && echo
	PID=$(pgrep -f "server.py" || true)
	if [ -d "$SSR_PATH" ]; then
		if [ -n "$PID" ]; then
			echo -e " 当前状态: $green已安装$plain 并 $green已启动$plain"
		else
			echo -e " 当前状态: $green已安装$plain 但 $red未启动$plain"
		fi
	else
		if [ -n "$PID" ]; then
			echo -e " 当前状态: $red已有其他ShadowsocksR在运行，请先卸载！$plain" && echo && exit 1
		else
			echo -e " 当前状态: $red未安装$plain"
		fi
	fi
	echo && read -p "请输入数字 [1-15]：" menu_num
	case "$menu_num" in
		1) InstallSsrMenu
		;;
		2) UninstallSsr
		;;
		3) InstallLibsodium
		;;
		4) ViewAccMenu
		;;
		5) ViewConnection
		;;
		6) ConfigAccMenu
		;;
		7) ConfigAccDiy
		;;
		8) ClearTransferMenu
		;;
		9) StartSsr
		;;
		10) StopSsr
		;;
		11) RestartSsr
		;;
		12) ViewLog
		;;
		13) OtherFunctions
		;;
		14) UpdateScript
		;;
		*)
		echo -e "$error 请输入正确的数字 [1-15]"
		;;
	esac
}

action=$*
case "$action" in
	"clearall") ClearTransferAll
	;;
	*) Menu
	;;
esac