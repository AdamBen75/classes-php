<?php

declare(strict_types=1);
session_start();

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

class User
{
    private ?int $id = null;
    public string $login = '';
    public string $email = '';
    public string $password = '';
    public string $firstname = '';
    public string $lastname = '';

    private mysqli $connexion;

    public function __construct()
    {
        $this->connexion = new mysqli("localhost", "root", "", "classes");
        if ($this->connexion->connect_error) {
            die("Erreur de connexion : " . $this->connexion->connect_error);
        }
    }

    private function validateInputs(string $login, string $email, string $password, string $firstname, string $lastname): ?string
    {
        if (empty($login) || empty($email) || empty($password) || empty($firstname) || empty($lastname)) {
            return "Tous les champs doivent être remplis.";
        }
        if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$.!%(+;)\*\/\-_{}#~$*%:!,<²°>ù^`|@[\]*?&]).{8,}$/', $password)) {
            return "Le mot de passe doit contenir au moins 8 caractères, avec majuscule, minuscule, chiffre et caractère spécial.";
        }
        return null;
    }

    public function register(string $login, string $email, string $password, string $firstname, string $lastname): array|string
    {
        if ($error = $this->validateInputs($login, $email, $password, $firstname, $lastname)) {
            return $error;
        }

        $hash = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->connexion->prepare("INSERT INTO utilisateurs (login, email, password, firstname, lastname) VALUES (?, ?, ?, ?, ?)");

        try {
            $stmt->bind_param("sssss", $login, $email, $hash, $firstname, $lastname);
            $stmt->execute();
        } catch (mysqli_sql_exception $e) {
            if ($e->getCode() === 1062) {
                return "Cet email existe déjà.";
            }
            return "Erreur SQL : " . $e->getMessage();
        }

        $this->id = $this->connexion->insert_id;
        $this->login = $login;
        $this->email = $email;
        $this->password = $hash;
        $this->firstname = $firstname;
        $this->lastname = $lastname;

        $_SESSION['user_id'] = $this->id;
        return $this->getAllInfos();
    }

    public function connect(string $login, string $password): bool|string
    {
        if (empty($login) || empty($password)) {
            return "Login et mot de passe requis.";
        }

        $stmt = $this->connexion->prepare("SELECT * FROM utilisateurs WHERE login = ?");
        $stmt->bind_param("s", $login);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($row = $result->fetch_assoc()) {
            if (password_verify($password, $row['password'])) {
                $this->fillFromRow($row);
                $_SESSION['user_id'] = $this->id;
                return true;
            }
        }

        return "Login ou mot de passe incorrect.";
    }

    public function loadFromSession(): bool
    {
        if (!isset($_SESSION['user_id'])) return false;
        $stmt = $this->connexion->prepare("SELECT * FROM utilisateurs WHERE id = ?");
        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($row = $result->fetch_assoc()) {
            $this->fillFromRow($row);
            return true;
        }
        return false;
    }

    private function fillFromRow(array $row): void
    {
        $this->id = (int)$row['id'];
        $this->login = $row['login'];
        $this->email = $row['email'];
        $this->password = $row['password'];
        $this->firstname = $row['firstname'];
        $this->lastname = $row['lastname'];
    }

    public function disconnect(): void
    {
        $this->id = null;
        $this->login = '';
        $this->email = '';
        $this->password = '';
        $this->firstname = '';
        $this->lastname = '';
        unset($_SESSION['user_id']);
    }

    public function delete(): string
    {
        if ($this->id) {
            $stmt = $this->connexion->prepare("DELETE FROM utilisateurs WHERE id = ?");
            $stmt->bind_param("i", $this->id);
            $stmt->execute();
            $stmt->close();
            $this->disconnect();
            return "Utilisateur supprimé.";
        }
        return "Aucun utilisateur connecté.";
    }

    public function update(string $login, string $email, string $password, string $firstname, string $lastname): string
    {
        if ($error = $this->validateInputs($login, $email, $password, $firstname, $lastname)) {
            return $error;
        }

        if ($this->id) {
            $hash = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $this->connexion->prepare("UPDATE utilisateurs SET login=?, email=?, password=?, firstname=?, lastname=? WHERE id=?");

            try {
                $stmt->bind_param("sssssi", $login, $email, $hash, $firstname, $lastname, $this->id);
                $stmt->execute();
            } catch (mysqli_sql_exception $e) {
                if ($e->getCode() === 1062) {
                    return "Cet email existe déjà.";
                }
                return "Erreur SQL : " . $e->getMessage();
            }

            $stmt->close();

            $this->login = $login;
            $this->email = $email;
            $this->password = $hash;
            $this->firstname = $firstname;
            $this->lastname = $lastname;

            return "Utilisateur mis à jour.";
        }
        return "Aucun utilisateur connecté.";
    }

    public function isConnected(): bool
    {
        return !empty($this->id);
    }

    public function getAllInfos(): array
    {
        return [
            "id" => $this->id,
            "login" => $this->login,
            "email" => $this->email,
            "firstname" => $this->firstname,
            "lastname" => $this->lastname
        ];
    }
}

$user = new User();
$message = '';
$user->loadFromSession();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'];
    $login = $_POST['login'] ?? '';
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $firstname = $_POST['firstname'] ?? '';
    $lastname = $_POST['lastname'] ?? '';

    switch ($action) {
        case 'register':
            $result = $user->register($login, $email, $password, $firstname, $lastname);
            $message = is_array($result) ? "Utilisateur créé avec succès." : $result;
            break;
        case 'connect':
            $result = $user->connect($login, $password);
            $message = $result === true ? "Connecté !" : $result;
            break;
        case 'disconnect':
            $user->disconnect();
            $message = "Déconnecté.";
            break;
        case 'update':
            $message = $user->update($login, $email, $password, $firstname, $lastname);
            break;
        case 'delete':
            $message = $user->delete();
            break;
    }
}
?>

<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestion Utilisateur</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
   <nav class="navbar">
    <a href="#" class="logo">Bienvenue</a>
    <div class="nav-links">
      <ul>
        <li class="active"><a href="user-pdo.php">PDO</a></li>
      </ul>
    </div>
  </nav>

    <header>

        <section>

        <h1>Gestion Utilisateur</h1>

        <?php if (!empty($message)): ?>
            <p class="message"><?= htmlspecialchars($message) ?></p>
        <?php endif; ?>

        <div class="input-box">
        <form method="post">
        <label for="login"></label>
        <input type ="text" id="login" name="login" placeholder="Login">
        </div>

        <div class="input-box">
        <label for="email"></label>
        <input type ="email" id="email" name="email" placeholder="Email">
        </div>

        <div class="input-box">
        <label for="password"></label>
        <input type ="password" id="password" name="password" placeholder="Password">
        </div>

        <div class="input-box">
        <label for="firstname"></label>
        <input type ="text" id="firstname" name="firstname" placeholder="Prénom">
        </div>

        <div class="input-box">
        <label for="lastname"></label>
        <input type ="text" id="lastname" name="lastname" placeholder="Nom">
        </div>

        <input class="login-btn" type="submit" value="register" name="action">
        <input class="login-btn" type="submit" value="connect" name="action">
        <input class="login-btn" type="submit" value="update" name="action">
        <input class="login-btn" type="submit" value="disconnect" name="action" formnovalidate>
        <input class="login-btn" type="submit" value="delete" name="action" formnovalidate>
    </form>

        </section>

</body>

</html>