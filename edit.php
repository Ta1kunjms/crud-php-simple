<?php
// Include the database connection file
require_once("dbConnection.php");

// Get id from URL parameter
$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;

if ($id <= 0) {
	header("Location:index.php");
	exit;
}

// Select data associated with this particular id
$result = mysqli_query($mysqli, "SELECT * FROM users WHERE id = $id");

// Fetch the next row of a result set as an associative array
$resultData = mysqli_fetch_assoc($result);

$name = $resultData['name'];
$age = $resultData['age'];
$email = $resultData['email'];
?>
<!DOCTYPE html>
<html lang="en">
<head>	
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Edit User</title>
	<link rel="stylesheet" href="styles.css">
</head>

<body>
	<div class="page-wrapper">
		<header class="topbar">
			<div>
				<h1>Edit User</h1>
				<p class="subtitle">Update details and save changes</p>
			</div>
			<div class="credit">TYCOON JAMES FLORES</div>
		</header>

		<main class="card">
			<p><a class="back-link" href="index.php">Back to Dashboard</a></p>
			<form name="edit" method="post" action="editAction.php" class="form-grid">
				<div>
					<label for="name">Name</label>
					<input type="text" id="name" name="name" value="<?php echo htmlspecialchars($name); ?>" required>
				</div>
				<div>
					<label for="age">Age</label>
					<input type="number" id="age" name="age" min="1" value="<?php echo htmlspecialchars($age); ?>" required>
				</div>
				<div>
					<label for="email">Email</label>
					<input type="email" id="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required>
				</div>
				<input type="hidden" name="id" value="<?php echo $id; ?>">
				<div class="form-actions">
					<button class="btn btn-primary" type="submit" name="update">Update User</button>
					<a class="btn btn-soft" href="index.php">Cancel</a>
				</div>
			</form>
		</main>
	</div>
</body>
</html>
