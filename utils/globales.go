package utils

import (
		"regexp"
		"database/sql"
)

var JWTSecret []byte = nil
var REAlfaNum = regexp.MustCompile(`^[\p{L}0-9]+$`)
var REEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
var BD *sql.DB

const (
		MsjResErrInterno = "Error interno en el sistema"
		MsjResErrFormIncorrecto = "Formulario incorrecto"
		MsjResErrUsrNoExiste = "Usuario no encontrado"
		MsjResErrCredInvalidas = "Credenciales invalidas"
		MsjResErrNoAutorizado = "No autorizado"
		MsjResAltaExito = "Alta exitosa"
		MsjResModExito = "Modificación exitosa"
		MsjResBajaExito = "Baja exitosa"
		MsjResExito = "Peticion exitosa"
)
