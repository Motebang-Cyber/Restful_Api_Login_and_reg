<?php
	header("Access-Control-Allow-Origin: *");
	header("Access-Control-Allow-Headers: access");
	header("Access-Control-Allow-Methods: POST");
	header("Content-Type: application/json; charset=UTF-8");
	header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-with");

	require __DIR__ . '/classes/Database.php';
	require __DIR__.'/classes/JwtHandler.php';

	function msg($success, $status, $message, $extra = []){
		return array_merge([
			'success' => $success,
			'status' => $status,
			'message' => $message
		], $extra);
	}

	$db_connection = new Database();
	$conn = $db_connection->dbConnection();

	$data = json_decode(file_get_contents("php://input"));
	$returnData = [];

	//IF REQUEST METHOD IS NIOT EQUAL TO POST
	if ($_SERVER["REQUEST_METHOD"] != "POST"):
		$returnData = msg(0,404, 'Page Not Found!');
	//CHECKING EMPY FIELDS
	elseif (!isset($data->email) 
		|| !isset($data->password)
		|| empty(trim($data->email))
		|| empty(trim($data->password))
		):

		$fields = ['fields' => ['email','password']];
		$returnData = msg(0,422,'Please Fill in all the required Fields!', $fields);
	//If THERE ARE NO EMPTY FIELDS THEN
	else:
		$email = trim($data->email);
		$password = trim($data->password);
		//CHECKING THE EMAIL FORMAT (IF INVALID FORMAT)
		if (!filter_var($email, FILTER_VALIDATE_EMAIL)):
			$returnData = msg(0, 422, 'Invalid Email Address!');
		//IF Password is less than 8 char show error message
		elseif(strlen($password) < 8):
			$returnData = msg(0, 422, 'Your password must be at least 8 charaters long!');
		//THE USER IS ABLE TO PERFORM THE LOGIN
		else:
			try{
				$fetch_user_by_email = "SELECT * FROM `users` WHERE `email`= :email";
				$query_stmt = $conn->prepare($fetch_user_by_email);
				$query_stmt->bindValue(':email', $email, PDO::PARAM_STR);
				$query_stmt->execute();
				//IF THE USER IS FOUND BY EMAIL
				if($query_stmt->rowCount()):
					$row = $query_stmt->fetch(PDO::FETCH_ASSOC);
					$check_password = password_verify($password, $row['password']);
					//VERIFYING THE PASSWORD (IS CORRECT OR NOT)
					//IF PASSWORD IS CORRECT THEN SEND THE LOGIN TOKEN
					if($check_password):
						$jwt = new JwtHandler();
						$token = $jwt->jwtEncodeData('http://localhost/php_auth_api/',array("user_id"=>$row['id']));

						$returnData = [
							'success' => 1,
							'message' => 'You have successfully logged in.',
							'token' => $token
						];
					//IF INVALID PASSWORD
					else:
						$returnData = msg(0, 422, 'Invalid password!');
					endif;
				//IF the user is not founded by Email then show the following error
				else:
					$returnData = msg(0,422, 'Invalid Email Address!');
				endif;
			}catch(PDOException $e){
				$returnData = msg(0, 500,$e->getMessage());
			}
		endif;
	endif;

echo json_encode($returnData);
?>
