<?php
 
$log_file_path = '/var/log/waf.log';

/**
 * [access 日志记录模块]
 * @return [type] [description]
 */
function access(){
	global $log_file_path;

	$flow = array(
                'Userip'=>$_SERVER['REMOTE_ADDR'],
                'Path' =>'http://'.$_SERVER['SERVER_NAME'].':'.$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"],
                'Post'=>$_POST,
		'Cookie'=>$_COOKIE,
		'Time'=> date('Y-m-s h:i:s',time())
		//'Request' => []
	);

	//$requestBody = file_get_contents('php://input');
	//$flow['Request']['Body'] = $rerequestBody;

	$log_path = $log_file_path;
	$log_content = json_encode($flow, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE| JSON_PRETTY_PRINT);
	if (file_put_contents($log_path,$log_content.PHP_EOL,FILE_APPEND) === false){
		error_log("Failed to write to log file: $log_path");
	}

	//$f = fopen($log_path,'a');
	//fwrite($f,"\n".json_encode($flow,true));
	//fclose($f);
}

$malicious_patterns = [
	"/@{1,2}.+?\s*/",//转义字符串匹配
	"/sleep\s*\(.*?\)/i",//匹配sleep()函数
	"/UNION.*SELECT/i",//匹配 union select
	"/(?i)(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)/",//匹配一些常见的数据库管理操作
	"/LOAD_FILE|OUTFILE/i"//文件注入
];

$req_params = array_merge($_GET, $_POST, $_COOKIE);
$add_log = 0;

foreach ($req_params as $key => $value){
	foreach ($malicious_patterns as $pattern){
		if (preg_match($pattern, $value)){
			access();
		        header("HTTP/1.1 403 Forbidden");
		        exit("Forbidden: Malicious input detected.");
		}
	}
}

echo "Hello, World! Your request has been processed.";

?>
