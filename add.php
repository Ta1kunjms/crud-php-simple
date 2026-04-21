<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Add User</title>
	<link rel="stylesheet" href="styles.css">
</head>

<body>
	<div class="page-wrapper">
		<header class="topbar">
			<div>
				<h1>Add New User</h1>
				<p class="subtitle">Create a new record quickly</p>
			</div>
			<div class="credit">TYCOON JAMES FLORES</div>
		</header>

		<main class="card">
			<p><a class="back-link" href="index.php">Back to Dashboard</a></p>
			<form action="addAction.php" method="post" name="add" class="form-grid">
				<div>
					<label for="name">Name</label>
					<input type="text" id="name" name="name" required>
				</div>
				<div>
					<label for="age">Age</label>
					<input type="number" id="age" name="age" min="1" required>
				</div>
				<div>
					<label for="email">Email</label>
					<input type="email" id="email" name="email" required>
				</div>
				<div class="form-actions">
					<button class="btn btn-primary" type="submit" name="submit">Add User</button>
					<a class="btn btn-soft" href="index.php">Cancel</a>
				</div>
			</form>
		</main>
	</div>
</body>
</html>

