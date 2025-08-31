DROP DATABASE IF EXISTS Autenticacion;
CREATE DATABASE Autenticacion;
USE Autenticacion;

CREATE TABLE Usuario(
    id INT AUTO_INCREMENT PRIMARY KEY,
    creado TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ult_mod TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE current_timestamp(),
    estado ENUM("ACTIVO","INACTIVO") DEFAULT "ACTIVO",

    usuario VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(50) UNIQUE NOT NULL,
    contra VARCHAR(500) NOT NULL,
    nombre VARCHAR(50) NULL,
    telefono VARCHAR(50) NULL,
    direccion VARCHAR(100) NULL    
);

CREATE TABLE Empresa(
    id INT AUTO_INCREMENT PRIMARY KEY,
    creado TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ult_mod TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE current_timestamp(),
    estado ENUM("ACTIVO","INACTIVO") DEFAULT "ACTIVO",
    
    nombre VARCHAR(50) NOT NULL,
    telefono VARCHAR(50) NULL,
    email VARCHAR(50) NULL,
    direccion VARCHAR(100) NULL
);

CREATE TABLE UsuarioEmpresa(
    usuario_id INT NOT NULL,
    empresa_id INT NOT NULL,
    PRIMARY KEY (usuario_id, empresa_id),
    FOREIGN KEY (usuario_id) REFERENCES Usuario(id) ON DELETE CASCADE,
    FOREIGN KEY (empresa_id) REFERENCES Empresa(id) ON DELETE CASCADE
);

CREATE TABLE Rol(
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE Permiso(
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE UsuarioRol (
    usuario_id INT NOT NULL,
    rol_id INT NOT NULL,
    PRIMARY KEY (usuario_id, rol_id),
    FOREIGN KEY (usuario_id) REFERENCES Usuario(id) ON DELETE CASCADE,
    FOREIGN KEY (rol_id) REFERENCES Rol(id) ON DELETE CASCADE
);

CREATE TABLE RolPermiso (
    rol_id INT NOT NULL,
    permiso_id INT NOT NULL,
    PRIMARY KEY (rol_id, permiso_id),
    FOREIGN KEY (rol_id) REFERENCES Rol(id) ON DELETE CASCADE,
    FOREIGN KEY (permiso_id) REFERENCES Permiso(id) ON DELETE CASCADE
);

CREATE TABLE Sesion (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    refresh_token VARCHAR(1000) NOT NULL,
    creado TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expira TIMESTAMP NOT NULL,
    activo BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (usuario_id) REFERENCES Usuario(id) ON DELETE CASCADE
);

-- indices para performance
CREATE INDEX idx_usuario_estado ON Usuario(estado);
CREATE INDEX idx_usuario_usuario ON Usuario(usuario);
CREATE INDEX idx_usuario_email ON Usuario(email);

CREATE INDEX idx_usuario_rol_usuario ON UsuarioRol(usuario_id);
CREATE INDEX idx_usuario_rol_rol ON UsuarioRol(rol_id);

CREATE INDEX idx_usuario_empresa_usuario ON UsuarioEmpresa(usuario_id);
CREATE INDEX idx_usuario_empresa_empresa ON UsuarioEmpresa(empresa_id);

CREATE INDEX idx_rol_permiso_rol ON RolPermiso(rol_id);
CREATE INDEX idx_rol_permiso_permiso ON RolPermiso(permiso_id);

CREATE INDEX idx_sesion_usuario ON Sesion(usuario_id);
CREATE INDEX idx_sesion_activo_expira ON Sesion(activo, expira);

DELIMITER $$
DROP EVENT IF EXISTS desactivar_sesiones_expiradas;
CREATE EVENT desactivar_sesiones_expiradas
ON SCHEDULE EVERY 1 DAY STARTS CURRENT_TIMESTAMP
DO UPDATE Sesion SET activo = FALSE WHERE expira < NOW() AND activo = TRUE;
$$

DELIMITER ;
