# discuz与mediawiki用户同步插件

[TOC]

## 简介
- 本程序用于Ucenter和mediawiki的用户同步登录
- 本程序是mediawiki的extension，基于mediawiki 1.24测试
- 本程序不仅仅是用户数据的同步，还实现了用户的同步登录和登出
- 新增用户权限的设计
- 本程序修改了官方扩展的代码,升级了uc_client为discuz3.2使用的1.6.0
- 本扩展mediawiki官方文档：[mediawiki官方文档](http://www.mediawiki.org/wiki/Extension:Discuz_X_Single_Sign-On)

## 配置说明
1. 复制DiscuzXSSO文件夹到extensions目录
2. 在`LocalSetting`中最后添加如下代码：
		
		$wgGroupPermissions['*']['createaccount'] = false;//禁止注册
		require_once "$IP/extensions/DiscuzXSSO/DiscuzXSSO.php";
		$wgAuth = new Auth_UCenter();
		// 下面这个函数在Setup.php调用，在mediawiki渲染页面之前插入我们的uc_login_hook 
		$wgExtensionFunctions[] = 'uc_login_hook';

3. 在`LocalSetting.php`添加权限控制:
	
		# The following permissions were set based on your choice in the installer
		$wgGroupPermissions['*']['createaccount'] = false;
		$wgGroupPermissions['*']['edit'] = false;
		$wgGroupPermissions['*']['createpage'] = false;
		$wgGroupPermissions['*']['createtalk'] = false;
		$wgGroupPermissions['*']['writeapi'] = false;

		# 取消user组的编辑权限
		$wgGroupPermissions['user']['edit'] = false;

		# 添加可编辑用户组
		$wgGroupPermissions['editor']['edit'] = true;
		$wgGroupPermissions['sysop']['edit'] = true;
 
4. 在Ucenter中添加应用，具体参考[mediawiki官方文档](http://www.mediawiki.org/wiki/Extension:Discuz_X_Single_Sign-On)
5. Ucenter数据库配置和cookie配置需修改`config.inc.php`，可参考discuz的`config_global.php`
6. 权限配置，修改`config.inc.php`中定义的`GP_`常量用于用户组归类
7. 修改wiki目录/includes/specials/SpecialUserLogin.php，在`attemptAutoCreate`方法最后一行的`return self::SUCCESS;`之前添加如下代码：
	
		echo "<script>location.reload();</script>";//解决新用户第一次登录wiki白板问题

## 用户权限特别说明
- 2015.1.20新增用户权限
- discuz的自动用户官方wiki会自动添加`用户(user)，自动确认用户(autoconfirmed)`用户组,所以通过取消`用户(user)`的编辑权限，添加`编辑者(editor)`的编辑权限来控制
- 新增editor用户组，如需修改中文用户组名(wiki1.24版本)：
	1. 在languages/i18n/zh-hans.json line 1059添加：`"group-editor":"编辑者",`
	2. 在line 1073添加`"grouppage-editor":"{{ns:project}}:编辑者",`
- 按上述配置的程序的权限：见wiki`特殊页面`-`用户组权限`
- discuz的用户对应到wiki分为三大类，见下表

| 					discuz        		| wiki          |
| --------------------------------------|:-------------:|
| 管理组(admin)      					| 管理员 		|
| 会员，高级会员，自定义组(normal) 		| 编辑者      	|
| 限制会员(limited)						| 限制用户      |


