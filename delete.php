<?php
// Include the database connection file
require_once("dbConnection.php");

// Get id parameter value from URL
$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;

// Delete row from the database table
if ($id > 0) {
	$result = mysqli_query($mysqli, "DELETE FROM users WHERE id = $id");
}

// Redirect to the main display page (index.php in our case)
header("Location:index.php");
exit;
