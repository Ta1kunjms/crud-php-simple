<?php
// Include the database connection file
require_once("dbConnection.php");

// Fetch data in descending order (lastest entry first)
$result = mysqli_query($mysqli, "SELECT * FROM users ORDER BY id DESC");
?>

<!DOCTYPE html>
<html lang="en">
<head>	
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Users Dashboard</title>
	<link rel="stylesheet" href="styles.css">
</head>

<body>
	<div class="page-wrapper">
		<header class="topbar">
			<div>
				<h1>CRUD Dashboard</h1>
				<p class="subtitle">Manage users with a clean modern interface</p>
			</div>
			<div class="credit">TYCOON JAMES FLORES</div>
		</header>

		<main class="card">
			<div class="card-header">
				<h2>User Records</h2>
				<a class="btn btn-primary" href="add.php">+ Add New User</a>
			</div>

			<div class="table-wrap">
				<table>
					<thead>
						<tr>
							<th>Name</th>
							<th>Age</th>
							<th>Email</th>
							<th>Action</th>
						</tr>
					</thead>
					<tbody>
						<?php
						// Fetch the next row of a result set as an associative array
						while ($res = mysqli_fetch_assoc($result)) {
							echo "<tr>";
							echo "<td>" . htmlspecialchars($res['name']) . "</td>";
							echo "<td>" . htmlspecialchars($res['age']) . "</td>";
							echo "<td>" . htmlspecialchars($res['email']) . "</td>";
							echo "<td class='actions'><a class='btn btn-soft' href=\"edit.php?id=$res[id]\">Edit</a>";
							echo "<a class='btn btn-danger' href=\"delete.php?id=$res[id]\" onClick=\"return confirm('Are you sure you want to delete this user?')\">Delete</a></td>";
							echo "</tr>";
						}
						?>
					</tbody>
				</table>
			</div>
		</main>
	</div>
</body>
</html>
