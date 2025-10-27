<?php
class User {

    private $id;
    public $login;
    public $email;
    public $firstname;
    public $lastname;
    private $isConnected = false;
    private $mysqli;

    public function __construct() {
        $this->mysqli = new mysqli("localhost", "root", "", "classes");
        if ($this->mysqli->connect_error) {
            die("Erreur de connexion MySQL : " . $this->mysqli->connect_error);
        }
    }

    public function register($login, $password, $email, $firstname, $lastname) {
        $stmt = $this->mysqli->prepare("SELECT * FROM utilisateurs WHERE login = ?");
        $stmt->bind_param("s", $login);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows == 0) {
            $hash = password_hash($password, PASSWORD_BCRYPT);
            $insert = $this->mysqli->prepare("INSERT INTO utilisateurs (login, password, email, firstname, lastname) VALUES (?, ?, ?, ?, ?)");
            $insert->bind_param("sssss", $login, $hash, $email, $firstname, $lastname);
            $insert->execute();

            $this->login = $login;
            $this->email = $email;
            $this->firstname = $firstname;
            $this->lastname = $lastname;

            return [
                'login' => $login,
                'email' => $email,
                'firstname' => $firstname,
                'lastname' => $lastname
            ];
        } else {
            return "Ce login existe déjà.";
        }
    }

    public function connect($login, $password) {
        $stmt = $this->mysqli->prepare("SELECT * FROM utilisateurs WHERE login = ?");
        $stmt->bind_param("s", $login);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($user = $result->fetch_assoc()) {
            if (password_verify($password, $user['password'])) {
                $this->id = $user['id'];
                $this->login = $user['login'];
                $this->email = $user['email'];
                $this->firstname = $user['firstname'];
                $this->lastname = $user['lastname'];
                $this->isConnected = true;
                return true;
            }
        }
        return false;
    }

    public function disconnect() {
        $this->id = null;
        $this->login = null;
        $this->email = null;
        $this->firstname = null;
        $this->lastname = null;
        $this->isConnected = false;
    }

    public function delete() {
        if ($this->isConnected && $this->id) {
            $stmt = $this->mysqli->prepare("DELETE FROM utilisateurs WHERE id = ?");
            $stmt->bind_param("i", $this->id);
            $stmt->execute();
            $this->disconnect();
            return true;
        }
        return false;
    }

    public function update($login, $password, $email, $firstname, $lastname) {
        if ($this->isConnected && $this->id) {
            $hash = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $this->mysqli->prepare("UPDATE utilisateurs SET login=?, password=?, email=?, firstname=?, lastname=? WHERE id=?");
            $stmt->bind_param("sssssi", $login, $hash, $email, $firstname, $lastname, $this->id);
            $stmt->execute();

            $this->login = $login;
            $this->email = $email;
            $this->firstname = $firstname;
            $this->lastname = $lastname;
            return true;
        }
        return false;
    }

    public function isConnected() {
        return $this->isConnected;
    }

    public function getAllInfos() {
        if ($this->isConnected) {
            return [
                'id' => $this->id,
                'login' => $this->login,
                'email' => $this->email,
                'firstname' => $this->firstname,
                'lastname' => $this->lastname
            ];
        }
        return null;
    }

    public function getLogin() {
        return $this->login;
    }

    public function getEmail() {
        return $this->email;
    }

    public function getFirstname() {
        return $this->firstname;
    }

    public function getLastname() {
        return $this->lastname;
    }

    public function setLogin($login) {
        $this->login = $login;
    }

    public function setEmail($email) {
        $this->email = $email;
    }

    public function setFirstname($firstname) {
        $this->firstname = $firstname;
    }

    public function setLastname($lastname) {
        $this->lastname = $lastname;
    }
}