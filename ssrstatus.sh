#!/usr/bin/env bash
set -euo pipefail

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+/Debian 7+/Ubuntu 14.04+
#	Description: ShadowsocksR Status
#	Version: 1.0.9
#	Author: Toyo
#	Rewriter: MTimer
#=================================================

sh_ver="1.0.9"
SSR_PATH="/usr/local/shadowsocksr"
if [ -d "/var/www" ]; then
	SSRSTATUS_ROOT="/var/www"
else
	SSRSTATUS_ROOT="/usr/local"
fi
SSRSTATUS_PATH="$SSRSTATUS_ROOT/SSRStatus"
LOG_FILE="$SSR_PATH/ssr_status.log"
CONFIG_FILE="$SSR_PATH/ssr_status.conf"
CRON_FILE="$SSR_PATH/ssr_status.cron"
JSON_FILE="$SSRSTATUS_PATH/json/stats.json"
SH_FILE="/usr/local/bin/ssrs"
timeout="10"
test_url="https://www.bing.com"

green="\033[32m"
red="\033[31m"
green_background="\033[42;37m"
red_background="\033[41;37m"
plain="\033[0m"
info="${green}[信息]$plain"
error="${red}[错误]$plain"
tip="${green}[注意]$plain"

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

	depends=(wget unzip vim curl crond)
	for depend in "${depends[@]}"; do
		DEPEND_PATH="$(command -v "$depend" || true)"
		if [ -z "$DEPEND_PATH" ]; then
			case "$release" in
				"rpm") yum -y install "$depend" >/dev/null 2>&1
				;;
				"deb"|"ubu") apt-get -y install "$depend" >/dev/null 2>&1
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

GetServerIp(){
    server_ip=$( ip addr | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -E -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z "$server_ip" ] && server_ip=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z "$server_ip" ] && server_ip=$( wget -qO- -t1 -T2 ipinfo.io/ip )
	[ -z "$server_ip" ] && server_ip=$( wget -qO- -t1 -T2 api.ip.sb/ip )
    [ -z "$server_ip" ] && echo "无法获取本机IP，请手动输入" && exit 1
}

SetAccIp(){
	echo "请输入 ShadowsocksR 账号服务器公网IP"
	read -p "(默认取消):" acc_ip
	[ -z "$acc_ip" ] && echo "已取消..." && exit 1
	echo && echo -e "	账号IP : $red$acc_ip$plain" && echo
}

SetAccPort(){
	echo "请输入 ShadowsocksR 账号端口"
	while read -p "(默认: 28989):" acc_port; do
		case $acc_port in
			("")
				acc_port=28989
				break
			;;
			(*[!0-9]*)
				echo -e "$error 请输入正确的数字！"
			;;
			(*)
				if [ $acc_port -ge 1 ] && [ $acc_port -le 65535 ]; then
					echo && echo -e "	端口: $red_background $acc_port $plain" && echo
					break
				else
					echo -e "$error 请输入正确的数字！"
				fi
			;;
		esac
	done
}

SetAccPasswd(){
	echo "请输入 ShadowsocksR 账号的密码"
	read -p "(默认: fuckyougfw):" passwd
	[ -z "$passwd" ] && passwd="fuckyougfw"
	echo && echo -e "	密码 : $red$passwd$plain" && echo
}

SetAccMethod(){
	echo -e "请选择要设置的ShadowsocksR账号 加密方式
 $green 1.$plain none
 
 $green 2.$plain rc4
 $green 3.$plain rc4-md5
 $green 4.$plain rc4-md5-6
 
 $green 5.$plain aes-128-ctr
 $green 6.$plain aes-192-ctr
 $green 7.$plain aes-256-ctr
 
 $green 8.$plain aes-128-cfb
 $green 9.$plain aes-192-cfb
 ${green}10.$plain aes-256-cfb
 
 ${green}11.$plain aes-128-cfb8
 ${green}12.$plain aes-192-cfb8
 ${green}13.$plain aes-256-cfb8
 
 ${green}14.$plain salsa20
 ${green}15.$plain chacha20
 ${green}16.$plain chacha20-ietf
 $tip salsa20/chacha20-*系列加密方式，需要额外安装依赖 libsodium ，否则会无法启动ShadowsocksR !" && echo
	read -p "(默认: 10. aes-256-cfb):" m_number
	methods=(
		none rc4 rc4-md5 rc4-md5-6 aes-128-ctr 
		aes-192-ctr aes-256-ctr aes-128-cfb aes-192-cfb 
		aes-256-cfb  aes-128-cfb8 aes-192-cfb8 aes-256-cfb8 
		salsa20 chacha20 chacha20-ietf 
	)
	method=${methods["$m_number" - 1]}
	[ -z "$method" ] && method=${methods[9]}
	echo && echo && echo -e "	加密 : $red$method$plain" && echo && echo
}

SetAccProtocol(){
	echo -e "请选择ShadowsocksR账号 协议插件
 ${green}1.$plain origin
 ${green}2.$plain auth_sha1_v4
 ${green}3.$plain auth_aes128_md5
 ${green}4.$plain auth_aes128_sha1
 ${green}5.$plain auth_chain_a
 ${green}6.$plain auth_chain_b" && echo
	read -p "(默认: 4. auth_aes128_sha1):" p_number
	protocols=(
		origin 
		auth_sha1_v4 
		auth_aes128_md5 
		auth_aes128_sha1 
		auth_chain_a
		auth_chain_b
	)
	protocol=${protocols["$p_number" - 1]}
	[ -z "$protocol" ] && protocol=${protocols[3]}

	echo && echo -e "	协议 : $red$protocol$plain" && echo
}

SetAccObfs(){
	echo -e "请选择ShadowsocksR账号 混淆插件
 ${green}1.$plain plain
 ${green}2.$plain http_simple
 ${green}3.$plain http_post
 ${green}4.$plain random_head
 ${green}5.$plain tls1.2_ticket_auth" && echo
	read -p "(默认: 5. tls1.2_ticket_auth):" o_number
	obfss=(
		plain 
		http_simple 
		http_post 
		random_head 
		tls1.2_ticket_auth
	)
	obfs=${obfss["$o_number" - 1]}
	[ -z "$obfs" ] && obfs=${obfss[4]}
	echo && echo -e "	混淆 : $red$obfs$plain" && echo
}

SetAccGroup(){
	echo "请输入 ShadowsocksR 账号的分组名称"
	read -p "(默认未分组):" acc_group
	[ -z "$acc_group" ] && acc_group="未分组"
	echo && echo -e "	分组 : $red$acc_group$plain" && echo
}

SetAccPublic(){
	echo "是否公开 ShadowsocksR 账号的密码?[Y/n]"
	read -p "(默认是):" acc_public
	[ -z "$acc_public" ] && acc_public="Y"
	if [[ "$acc_public" == [Yy] ]]; then
		acc_public="show"
		acc_public_text="公开"
	else
		acc_public="hide"
		acc_public_text="隐藏"
	fi
	echo && echo -e "	密码状态 : $green$acc_public_text$plain" && echo
}

DecAccLink(){
	IFS='://' read acc_type acc_info <<< "$acc_link"
	acc_info=$(echo "$acc_info"|base64 --decode)
	if [ "$acc_type" == "ss" ]; then
		IFS=':' read method passwd_ip acc_port <<< "$acc_info"
		IFS='@' read passwd acc_ip <<< "$passwd_ip"
		protocol="origin"
		obfs="plain"
	else
		acc_info_a=$(echo "$acc_info"|awk -F "/?" '{print $1}')
		IFS=':' read acc_ip acc_port protocol method obfs passwd_base64 <<< "$acc_info_a"
		passwd=$(echo "$passwd_base64"|base64 --decode)
		acc_info_b=$(echo "$acc_info"|awk -F "/?" '{print $2}')
		acc_info_c=$(echo "$acc_info_b"|awk -F "group=" '{print $2}')
		group_base64=$(echo "$acc_info_c"|awk -F "=" '{print $1}')
		acc_group=$(echo "$group_base64"|base64 --decode)
	fi
	[ -z "$acc_group" ] && acc_group="未分组"
	echo && echo -e "	链接 : $red$acc_link$plain" && echo
}

ListAccs(){
	[ ! -e "$CONFIG_FILE" ] && echo -e "$error 配置文件不存在！($CONFIG_FILE)" | tee -a "$CONFIG_FILE" && exit 1
	accs=$(cat "$CONFIG_FILE")
	[ -z "$accs" ] && echo -e "$error 获取SS/SSR账号信息失败或配置文件为空 !" | tee -a "$LOG_FILE" && exit 1
	accs_num=$(echo -e "$accs"|wc -l)
	echo -e "目前有 $accs_num 个账号配置\n$(echo -e "$accs"|grep -n "###")"
}

AddAcc(){
	if echo "$acc" >> "$CONFIG_FILE" ; then
		echo -e "$info 添加成功 ! [$acc]"
	else
		echo -e "$error 添加失败 ! [$acc]"
	fi
}

DelAcc(){
	ListAccs
	[ "$accs_num" == "0" ] && echo -e "$error 没有账号!" && exit 1
	echo "请选择你要删除的账号序号"
	while read -p "(默认取消):" del_num; do
		case "$del_num" in
			("")
				echo "已取消..." && exit 1
			;;
			(*[!0-9]*)
				echo -e "$error 请输入正确的数字！"
			;;
			(*)
				if [ "$del_num" -ge 1 ] && [ "$del_num" -le "$accs_num" ]; then
					break;
				else
					echo -e "$error 请输入正确的数字！"
				fi
			;;
		esac
	done
	if [ "$(sed -i "$del_num"d "$CONFIG_FILE")" ]; then
		echo -e "$info 删除成功 ! [$del_num]"
	else
		echo -e "$error 删除失败 ! [$del_num]"
	fi
}

ConfigAcc(){
	ListAccs
	[ "$accs_num" == "0" ] && echo -e "$error 没有账号!" && exit 1
	while read -p "(默认取消):" config_num; do
		case "$config_num" in
			("")
				echo "已取消..." && exit 1
			;;
			(*[!0-9]*)
				echo -e "$error 请输入正确的数字！"
			;;
			(*)
				if [ "$config_num" -ge 1 ] && [ "$config_num" -le "$accs_num" ]; then
					break;
				else
					echo -e "$error 请输入正确的数字！"
				fi
			;;
		esac
	done
	AddAccMenu
	sed -i "${config_num} c\\${acc}" "${CONFIG_FILE}"
}

ConfigAccStatus(){
	ListAccs
	[ "$accs_num" == "0" ] && echo -e "$error 没有账号!" && exit 1
	echo -e "请选择你要启用/禁用的账号序号"
	while read -p "(默认取消):" config_status_num; do
		case "$config_status_num" in
			("")
				echo "已取消..." && exit 1
			;;
			(*[!0-9]*)
				echo -e "$error 请输入正确的数字！"
			;;
			(*)
				if [ "$config_status_num" -ge 1 ] && [ "$config_status_num" -le "$accs_num" ]; then
					break;
				else
					echo -e "$error 请输入正确的数字！"
				fi
			;;
		esac
	done

	acc=$(echo -e "$accs"|sed -n "${config_status_num}"p)
	acc_status=$(echo -e "$acc"|awk -F '###' '{print $4}')
	case "$acc_status" in
		"offline")
			echo -e "$error 修改失败 ! 无法修改离线账号状态!" && exit 1
		;;
		"disabled")
			acc=$(echo -e "$acc"|sed 's;disabled;enabled;')
			acc_status_old="禁用"
			acc_status_new="启用"
		;;
		"enabled")
			acc=$(echo -e "$acc"|sed 's;enabled;disabled;')
			acc_status_old="启用"
			acc_status_new="禁用"
		;;
		*)
			echo -e "$error 修改失败 ! 无法查询账号状态 !" && exit 1
		;;
	esac

	if [ "$(sed -i "${config_status_num} c\\${acc}" "$CONFIG_FILE")" ]; then
		echo -e "$info 修改成功 ! [账号状态为: $green$acc_status_new$plain]"
	else
		echo -e "$error 修改失败 ! [账号状态为: $red$acc_status_old$plain]"
	fi
}

AddAccMenu(){
	echo -e "请选择输入方式
 ${green}1.$plain 输入ShadowsocksR账号全部信息(Shadowsocks原版也可以)
 ${green}2.$plain 输入ShadowsocksR账号的 SSR链接(Shadowsocks原版也可以)"
	read -p "(默认:2):" add_acc_num
	[ -z "$add_acc_num" ] && add_acc_num="2"
	if [ "$add_acc_num" == "1" ]; then
		echo "下面依次开始输入要检测的 ShadowsocksR账号信息。" && echo
		SetAccIp
		SetAccPort
		SetAccPasswd
		SetAccMethod
		SetAccProtocol
		SetAccObfs
		SetAccGroup
		SetAccPublic
	else
		echo "请输入 ShadowsocksR 的链接(SS/SSR链接皆可，如 ss://xxxx ssr://xxxx)"
		read -p "(默认回车取消):" acc_link
		[ -z "$acc_link" ] && echo "已取消..." && exit 1
	fi
	acc_status="enabled"

	[ -n "$acc_link" ] && DecAccLink
	ValidIP
	if [ "$acc_type" == "ss" ]; then
		acc_link="ss://"$(echo -n "$method:$passwd@$acc_ip:$acc_port"|base64 -w0 |sed 's/=//g;s/\//_/g;s/+/-/g')
	else
		passwd_base64=$(echo -n "$passwd"|base64 -w0 |sed 's/=//g;s/\//_/g;s/+/-/g')
		group_base64=$(echo -n "$acc_group"|base64 -w0 |sed 's/=//g;s/\//_/g;s/+/-/g')
		acc_link="ssr://"$(echo -n "$acc_ip:$acc_port:$protocol:$method:$obfs:$passwd_base64/?group=$group_base64"|base64 -w0 |sed 's/=//g;s/\//_/g;s/+/-/g')
	fi
	acc="$acc_link###$acc_group###$acc_public###enbaled"
}

ConfigAccMenu(){
	echo && echo -e " 你要做什么？
	
 $green 1.$plain 添加 账号配置
 $green 2.$plain 删除 账号配置
 $green 3.$plain 修改 账号配置
————————
 $green 4.$plain 启用/禁用 账号配置
 注意：添加/修改/删除 账号配置后，不会立即更新，需要自动(定时)/手动检测一次所有账号，网页才会更新 !" && echo
	read -p "(默认: 取消):" config_acc_num
	[ -z "$config_acc_num" ] && echo "已取消..." && exit 1
	if [ "$config_acc_num" == "1" ]; then
		AddAccMenu
		AddAcc
	elif [ "$config_acc_num" == "2" ]; then
		DelAcc
	elif [ "$config_acc_num" == "3" ]; then
		ConfigAcc
	elif [ "$config_acc_num" == "4" ]; then
		ConfigAccStatus
	else
		echo -e "$error 请输入正确的数字[1-4]" && exit 1
	fi
}

SetServerName(){
	echo "请输入 SSRStatus 网站要设置的 域名[server]
默认为本机IP为域名，例如输入: domain.com，如果要使用本机IP，请留空直接回车"
	read -p "(默认: 本机IP):" server_name
	[ -z "$server_name" ] && GetServerIp && server_name=$server_ip
	echo && echo -e "	IP/域名[server]: $red_background $server_name $plain" && echo
}

SetServerPort(){
	echo "请输入 SSRStatus 网站要设置的 域名/IP的端口[1-65535]（如果是域名的话，一般建议用 http 80 端口）"
	while read -p "(默认: 8888):" server_port; do
		case "$server_port" in
			("")
				server_port=8888
			;;
			(*[!0-9]*)
				echo -e "$error 请输入正确的端口！"
			;;
			(*)
				if [ "$server_port" -ge 1 ] && [ "$server_port" -le 65535 ]; then
					echo && echo -e "	IP/域名[server]: $red_background $server_port $plain" && echo
					break;
				else
					echo -e "$error 请输入正确的端口！"
				fi
			;;
		esac
	done
}

ViewStatusLog(){
	[ ! -e $LOG_FILE ] && echo -e "$error 找不到 日志文件！($LOG_FILE)"
	echo && echo -e "$tip 按 ${red}Ctrl+C$plain 终止查看日志" && echo -e "如果需要查看完整日志内容，请用 ${red}cat $LOG_FILE$plain 命令。" && echo
	tail -f "$LOG_FILE"
}

UpdateJson(){
	acc_time=$(date '+%Y-%m-%d %H:%M:%S')
	if [ "$1" == "$accs_num" ]; then
		config_json="${config_json}{ \"acc_ip\": \"$acc_ip:$acc_port\", \"acc_group\": \"$acc_group\", \"method\": \"$method\", \"protocol\": \"$protocol\", \"obfs\": \"$obfs\", \"acc_type\": \"$acc_type\", \"acc_public\": \"$acc_public\", \"acc_status\": $acc_status, \"acc_time\": $acc_time  }\n"
		config_json="{\n\"servers\": [\n${config_json}],\n\"updated\": \"$(date +%s)\"\n}"
	else
		config_json="${config_json}{ \"acc_ip\": \"$acc_ip:$acc_port\", \"acc_group\": \"$acc_group\", \"method\": \"$method\", \"protocol\": \"$protocol\", \"obfs\": \"$obfs\", \"acc_type\": \"$acc_type\", \"acc_public\": \"$acc_public\", \"acc_status\": $acc_status, \"acc_time\": $acc_time  },\n"
	fi
}

RandPort(){
    read lowerport upperport < /proc/sys/net/ipv4/ip_local_port_range
    while :
    do
            rand_port=$(shuf -i "$lowerport"-"$upperport" -n 1)
            ss -lpn | grep -q ":$rand_port " || break
    done
    # OR rand_port=$(python -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()');
}

ValidIP(){
	re='^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}'
	re+='0*(1?[0-9]{1,2}|2([‌​0-4][0-9]|5[0-5]))$'
	if [[ ! $acc_ip =~ $re ]]; then
		echo -e "$error 错误，IP格式错误[ $acc_ip ]" | tee -a "$LOG_FILE"
	fi
}

LogStart(){
	echo -e "========== 开始记录测试信息 [$(date '+%Y-%m-%d %H:%M:%S')]==========\n" >> "$LOG_FILE"
}

LogEnd(){
	echo -e "========== 记录测试信息结束 [$(date '+%Y-%m-%d %H:%M:%S')]==========\n\n" >> "$LOG_FILE"
}

TestOneAcc(){
	[ -n "$acc_link" ] && DecAccLink
	ValidIP

	if [ "$acc_type" == "ss" ]; then
		echo -e "$method:$passwd@$acc_ip:$acc_port"
	else
		echo -e "$acc_ip:$acc_port:$protocol:$method:$obfs:$passwd_base64/?group=$group_base64"	
	fi

	if [ -z "$acc_ip" ] || [ -z "$acc_port" ] || [ -z "$method" ] || [ -z "$passwd" ] || [ -z "$protocol" ] || [ -z "$obfs" ]; then
		echo -e "$error 错误，有部分 账号参数为空！[ $acc_ip ,$acc_port ,$method ,$passwd ,$protocol ,$obfs ]" | tee -a "$LOG_FILE"
	fi

	RandPort
	nohup python "$SSR_PATH/shadwosocks/local.py" -b "127.0.0.1" -l "$rand_port" -s "$server_ip" -p "$server_port" -k "$passwd" -m "$method" -O "$protocol" -o "$obfs" > /dev/null 2>&1 &
	sleep 2s
	
	PID=$(pgrep -f "local.py" | grep "$rand_port")

	[ -z "$PID" ] && echo -e "$error ShadowsocksR客户端 启动失败，请检查 !" | tee -a "$LOG_FILE"

	test_results=$(curl --socks5 127.0.0.1:"$rand_port" -k -m "$timeout" -s "$test_url")
	if [ -z "$test_results" ]; then
		echo -e "$error [$acc_ip] 检测失败，账号不可用，重新尝试一次..." | tee -a $"$LOG_FILE"
		sleep 2s
		test_results=$(curl --socks5 127.0.0.1:"$rand_port" -k -m ${timeout} -s "$test_url")
		if [ -z "$test_results" ]; then
			acc_status="offline"
			echo -e "$error [$acc_ip] 检测失败，账号不可用(已重新尝试) !" | tee -a "$LOG_FILE"
		else
			acc_status="enabled"
			echo -e "$info [$acc_ip] 检测成功，账号可用 !" | tee -a "$LOG_FILE"
		fi
	else
		acc_status="enabled"
		echo -e "$info [$acc_ip] 检测成功，账号可用 !" | tee -a "$LOG_FILE"
	fi
	kill -9 "$PID"

	if ! pgrep -f "local.py"|grep -q "$rand_port" ; then
		echo -e "$error ShadowsocksR客户端 停止失败，请检查 !" | tee -a "$LOG_FILE"
	fi
	echo "---------------------------------------------------------"
}

TestAllAccs(){
	ListAccs
	LogStart
	config_json=""
	for((integer = 1; integer <= "$accs_num"; integer++)); do
		acc=$(echo -e "$accs"|sed -n "$integer"p)
		IFS='###' read acc_link acc_group acc_public acc_status <<< "$acc"
		if [ "$acc_status" != "disabled" ]; then
			TestOneAcc
			UpdateJson "$integer"
		fi
	done
	echo -e "$config_json" > "$JSON_FILE"
	LogEnd
}

TestOneAccMenu(){
	ListAccs
	LogStart
	echo "请选择你要单独测试的账号序号"
	while read -p "(默认取消):" test_acc_num; do
		case "$test_acc_num" in
			("")
				echo "已取消..." && exit 1
			;;
			(*[!0-9]*)
				echo -e "$error 请输入正确的数字！"
			;;
			(*)
				if [ "$test_acc_num" -ge 1 ] && [ "$test_acc_num" -le "$accs_num" ]; then
					break;
				else
					echo -e "$error 请输入正确的数字！"
				fi
			;;
		esac
	done

	acc=$(echo -e "$accs"|sed -n "$test_acc_num"p)
	IFS='###' read acc_link acc_group acc_public acc_status <<< "$acc"
	if [ "$acc_status" != "disabled" ]; then
		TestOneAcc
	fi
	LogEnd
}

TestNewAcc(){
	AddAccMenu
	TestOneAcc
	LogEnd
}

ChangeDate(){
	rm -rf /etc/localtime
	ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}

UpdateCron(){
	[ -z $release ] && CheckRelease
	case "$release" in
		"rpm") /etc/init.d/crond restart
		;;
		"deb") /etc/init.d/cron restart
		;;
		*) echo "$error 重启cron发生错误!"
		;;
	esac
}

CrontabMenu(){
	[ ! -d "$SSRSTATUS_PATH" ] && echo -e "$error SSRStatus 网页文件没有安装，请检查 !" && exit 1
	echo -e "请选择你要设置的ShadowsocksR账号检测时间间隔（如账号很多，请不要设置时间间隔过小）
 ${green}1.$plain 5分钟
 ${green}2.$plain 10分钟
 ${green}3.$plain 20分钟
 ${green}4.$plain 30分钟
 ${green}5.$plain 40分钟
 ${green}6.$plain 50分钟
 ${green}7.$plain 1小时
 ${green}8.$plain 2小时
 ${green}9.$plain 自定义输入" && echo
	read -p "(默认: 2. 10分钟):" c_number
	crontabs=(
		"*/5 * * * *" 
		"*/10 * * * *" 
		"*/20 * * * *" 
		"*/30 * * * *" 
		"*/40 * * * *" 
		"*/50 * * * *" 
		"0 * * * *" 
		"0 */2 * * *" 
	)
	if [ "$c_number" == "9" ]; then
		CrontabCustom
	else
		cron_time=${crontabs["$c_number" - 1]}
		[ -z "$cron_time" ] && cron_time=${crontabs[1]}
	fi
	echo && echo -e "	间隔时间 : $red$cron_time$plain" && echo
	AddCrontab
}

AddCrontab(){
	crontab -l > "$CRON_FILE"
	sed -i "/ssrs/d" "$CRON_FILE"
	echo -e "\n$cron_time /bin/bash $SH_FILE t" >> "$CRON_FILE"
	crontab "$CRON_FILE"
	cron_config=$(crontab -l | grep "ssrs")
	if [ -z "$cron_config" ]; then
		echo -e "$error 添加 Crontab 定时任务失败 !" && exit 1
	else
		echo -e "$info 添加 Crontab 定时任务成功 !"
	fi
}

DelCrontab(){
	crontab -r "$CRON_FILE"
	cron_config=$(crontab -l | grep "ssrs")
	if [ -n "$cron_config" ]; then
		echo -e "$error 删除 Crontab 定时任务失败 !" && exit 1
	else
		echo -e "$info 删除 Crontab 定时任务成功 !"
	fi
	sed -i "/ssrs/d" "$CRON_FILE"
	rm -rf "$CRON_FILE"
}

CrontabCustom(){
	echo -e "请输入ShadowsocksR账号检测时间间隔（如账号很多，请不要设置时间间隔过小）
 === 格式说明 ===
 * * * * * 分别对应 分钟 小时 日份 月份 星期
 $green */10 * * * * $plain 代表每10分钟 检测一次
 $green 0 */2 * * * $plain 代表每2小时的0分 检测一次
 $green 10 * * * * $plain 代表每小时的第10分 检测一次
 $green * 2 * * * $plain 代表每天的第2点 检测一次
 $green 0 0 2 * * $plain 代表每2天的0点0分 检测一次" && echo
	read -p "(默认: */10 * * * *):" cron_time
	[ -z "$cron_time" ] && cron_time="*/10 * * * *"
}

InstallCaddy(){
	echo "是否由脚本自动配置HTTP服务(在线监控网站)[Y/n]"
	read -p "(默认: Y 自动部署):" install_caddy_yn
	[ -z "$install_caddy_yn" ] && install_caddy_yn="y"
	if [[ "$install_caddy_yn" == [Yy] ]]; then
		SetServerName
		SetServerPort
		wget -qO --no-check-certificate https://raw.githubusercontent.com/woniuzfb/doubi/master/caddy_install.sh
		chmod +x caddy_install.sh
		bash caddy_install.sh install
		[ ! -e "$SSRSTATUS_PATH/caddy" ] && echo -e "$error Caddy安装失败，请手动部署，Web网页文件位置：$SSRSTATUS_PATH" && exit 1

		cat >> "$SSRSTATUS_PATH/Caddyfile"<<-EOF
		http://$server_name:$server_port {
			root $SSRSTATUS_PATH
			timeouts none
			gzip
		}
		EOF
		/etc/init.d/caddy restart
	else
		echo -e "$info 跳过 HTTP服务部署，请手动部署，Web网页文件位置：$SSRSTATUS_PATH !"
	fi
}

DownloadStatus(){
	wget --no-check-certificate -qO "https://github.com/woniuzfb/doubi/archive/master.zip"
	[ ! -e "./master.zip" ] && echo -e "$error SSRStatus 网页文件下载失败 !" && exit 1
	unzip "./master.zip" && rm -rf "./master.zip"
	[ ! -e "./doubi-master" ] && echo -e "$error SSRStatus 网页文件解压失败 !" && exit 1
	mv "./doubi-master/web/SSRStatus" "$SSRSTATUS_ROOT/"
	[ ! -e "$SSRSTATUS_PATH" ] && echo -e "$error SSRStatus 网页文件文件夹重命名失败 !" && exit 1
}

InstallStatus(){
	[ -d "$SSRSTATUS_PATH" ] && echo -e "$error 检测到 SSRStatus 网页文件已安装 !" && exit 1
	echo -e "$info 开始配置 依赖..."
	CheckRelease
	ChangeDate
	UpdateCron
	echo -e "$info 开始部署HTTP服务(Caddy)..."
	InstallCaddy
	echo -e "$info 开始下载/安装..."
	DownloadStatus
	echo -e "$info 开始配置定时任务..."
	CrontabMenu
	echo -e "$info 所有步骤 安装完毕... 请打开本脚本并修改开头的 SSR_PATH 变量引号内的ShadowsocksR目录，方可使用。"
}

UninstallStatus(){
	[ ! -d "$SSRSTATUS_PATH" ] && echo -e "$error SSRStatus 网页文件没有安装，请检查 !" && exit 1
	echo "确定要卸载 SSRStatus 网页文件(自动部署的Caddy并不会删除) ? [y/N]"
	echo
	read -p "(默认: 否):" uninstall_status_yn
	[ -z "$uninstall_status_yn" ] && uninstall_status_yn="n"
	if [[ "$uninstall_status_yn" == [Yy] ]]; then
		/etc/init.d/caddy stop
		DelCrontab
		rm -rf "$SSRSTATUS_PATH"
		echo && echo "SSRStatus 网页文件卸载完成 !" && echo
	else
		echo && echo "卸载已取消..." && echo
	fi
}

UpdateShell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/woniuzfb/doubi/master/ssrstatus.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[ -z "$sh_new_ver" ] && echo -e "$error 无法链接到 Github !" && exit 1
	wget --no-check-certificate -qO "$SH_FILE" "https://raw.githubusercontent.com/woniuzfb/doubi/master/ssrstatus.sh" && chmod +x "$SH_FILE"
	echo -e "脚本已更新为最新版本[ $sh_new_ver ] !(输入: ssrs 使用)" && exit 0
}

Menu(){
	[ -e "$SH_FILE" ] && wget --no-check-certificate -qO "$SH_FILE" "https://raw.githubusercontent.com/woniuzfb/doubi/master/ssrstatus.sh" && chmod +x "$SH_FILE"
	echo && echo -e "  SSRStatus 一键安装管理脚本 ${red}[v$sh_ver]$plain
	-- Toyo | rewriting by MTimer --
	
	${green}0.$plain 升级脚本
	————————————
	${green}1.$plain 安装 依赖及Web网页
	${green}2.$plain 卸载 依赖及Web网页
	————————————
	${green}3.$plain 测试 所有账号
	${green}4.$plain 测试 单独账号
	${green}5.$plain 测试 自定义账号
	————————————
	${green}6.$plain 设置 账号
	${green}7.$plain 查看 账号
	${green}8.$plain 查看 日志
	${green}9.$plain 设置 计划任务
	————————————" && echo
	[ -d "$SSRSTATUS_PATH" ] && echo -e " 当前状态: Web网页 $green已安装$plain" || echo -e " 当前状态: Web网页 $red未安装$plain"
	echo
	read -p " 请输入数字 [0-9]:" choose
	case "$choose" in
		0)
		UpdateShell
		;;
		1)
		InstallStatus
		;;
		2)
		UninstallStatus
		;;
		3)
		TestAllAccs
		;;
		4)
		TestOneAccMenu
		;;
		5)
		TestNewAcc
		;;
		6)
		ConfigAccMenu
		;;
		7)
		ListAccs
		;;
		8)
		ViewStatusLog
		;;
		9)
		CrontabMenu
		;;
		*)
		echo "请输入正确数字 [0-9]"
		;;
	esac
}

action=$1
case "$action" in
	t) TestAllAccs
	;;
	o) TestOneAccMenu
	;;
	a) TestNewAcc
	;;
	log) ViewStatusLog
	;;
	*) Menu
	;;
esac