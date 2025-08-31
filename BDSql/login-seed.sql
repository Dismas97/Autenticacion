INSERT INTO Usuario (estado,usuario,contra,email) VALUES
("ACTIVO", "fran", "$2a$10$GwuLXIm2pFBq5KOUc27VjOqiNAv.sQ3rj8YgwooVcF7vxGgeviEr2","fran1@gmail.com"),
("ACTIVO", "fran2", "$2a$10$3Y0ACtiagET0hasOs2zs3OXFj18gUGZX247OeNQS6DW0M..IcVbKO","fran2@gmail.com"),
("ACTIVO", "fran3", "$2a$10$idqTko6.OM4hxae7Omn/3OZqCNSUtsnMWWQ2w7G1GaOcqVVdJVc8u","fran3@gmail.com");

INSERT INTO Rol (nombre) VALUES
('ADMIN'),
('EMPLEADO'),
('USUARIO');

INSERT INTO Permiso (nombre) VALUES
('USUARIO_ALTA'),
('USUARIO_BAJA'),
('USUARIO_LISTAR'),
('USUARIO_MODIFICAR');

INSERT INTO RolPermiso (rol_id, permiso_id) VALUES
(1, 1),
(1, 2),
(1, 3),
(1, 4),
(2, 3);

INSERT INTO UsuarioRol
(usuario_id,rol_id)
VALUES
(1,1),
(2,2),
(3,3);
