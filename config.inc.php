<?php
/******************************************/
define('UC_CONNECT', 'uc_api_post');
define('UC_DBHOST', 'localhost');
define('UC_DBUSER', 'root');
define('UC_DBPW', '123456');
define('UC_DBNAME', 'dz25_2');
define('UC_DBCHARSET', 'utf8');
define('UC_DBTABLEPRE', '`dz25_2`.bbs_ucenter_');
define('DZ_DBTABLEPRE','`dz25_2`.bbs_');
define('UC_DBCONNECT', '0');
define('UC_KEY', 'ucloginmediawiki');
define('UC_API', 'http://localhost/bbs/uc_server');
define('UC_CHARSET', 'utf-8');
define('UC_IP', '127.0.0.1');
define('UC_APPID', '2');
define('UC_PPP', '20');

//定义cookie和安全性的一些东西，从discuz的config_global.php中获得
define('COOKIE_PRE', 'sq2e_');
define('COOKIE_DOMAIN','');
define('COOKIE_PATH', '/');
define('SECURITY_AUTHKEY','9cf458jRumF9jCSN');

//定义用户组和discuz中的groupid的对应关系,请按格式写，半角逗号分隔
define('GP_LIMITED','4,5,6,7,8,9,17');
define('GP_NORMAL','2,3,18,19,20,21,22,23,24,25,27');
define('GP_ADMIN','1');

/******************************************/

//用到的应用程序数据库连接参数
$dbhost = UC_DBHOST;			// 数据库服务器
$dbuser = UC_DBUSER;			// 数据库用户名
$dbpw = UC_DBPW;				// 数据库密码
$dbname = UC_DBNAME;			// 数据库名
$uc_tablepre = UC_DBTABLEPRE;   		// 表名前缀, 同一数据库安装多个论坛请修改此处
$pconnect = UC_DBCONNECT;				// 数据库持久连接 0=关闭, 1=打开
$dbcharset = UC_CHARSET;			// MySQL 字符集, 可选 'gbk', 'big5', 'utf8', 'latin1', 留空为按照论坛字符集设定

//上面的变量在DiscuzXSSO.php中的方法内是无法访问的,在DiscuzXSSO.php 70多行有重新赋值