<?php 
	header("Access-Control-Allow-Origin: *");
	header("Access-Control-Allow-Headers: access");
	header("Access-Control-Allow-Methods: GET");
	header("Content-Type: application/json; charset=UTF-8");
	header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

	require __DIR__.'/classes/Database.php';
	require __DIR__.'/AuthMiddleware.php';

	//$allheader = getallheaders();
	$db_connection = new Database();
	$conn = $db_connection->dbconnection();
	$auth = new Auth($conn, getallheaders());

	echo json_encode($auth->isValid()); 
?>