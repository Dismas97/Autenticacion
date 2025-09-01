package controles

import (
		"encoding/json"
		"errors"
		"fran/sqlstruct"
		"fran/utils"
		"net/http"
		_ "github.com/go-sql-driver/mysql"
		"github.com/labstack/echo/v4"
		log "github.com/sirupsen/logrus"
		"golang.org/x/crypto/bcrypt"
)

var err error = nil

type Usuario struct {
		Usuario string `json:"usuario" form:"usuario"`
		Contra  string `json:"contra" form:"contra"`
		Email string `json:"email" form:"email"`
		Nombre *string `json:"nombre" form:"nombre"`
		Telefono *string `json:"telefono" form:"telefono"`
		Direccion *string `json:"direccion" form:"direccion"`
}

type UsuarioDetallado struct {
		Id int `json:"id" form:"id"`
		Usuario string `json:"usuario" form:"usuario"`
		Contra  string `json:"contra" form:"contra"`
		Email string `json:"email" form:"email"`
		Nombre *string `json:"nombre" form:"nombre"`
		Telefono *string `json:"telefono" form:"telefono"`
		Direccion *string `json:"direccion" form:"direccion"`
		Roles *string `json:"roles" form:"roles"`
}

type UsuarioDetalladoRes struct {
		Id int `json:"id" form:"id"`
		Usuario string `json:"usuario" form:"usuario"`
		Email string `json:"email" form:"email"`
		Nombre *string `json:"nombre" form:"nombre"`
		Telefono *string `json:"telefono" form:"telefono"`
		Direccion *string `json:"direccion" form:"direccion"`
		Roles []RolRes `json:"roles" form:"roles"`
}

type LoginRequest struct {
		Usuario string `json:"usuario"`
		Contra string `json:"contra"`
}

func chequeoQueryData(fuente map[string]any, campos []string) error {
		for i := range campos {
				log.Debug(fuente[campos[i]])
				if fuente[campos[i]] == nil || fuente[campos[i]] == ""{
						return errors.New("campo "+campos[i]+" no exportado")
				}
		}
		return nil
}

func getUsuario(campo string, valor string) (UsuarioDetallado, error) {
		query := `SELECT u.id, u.usuario, u.contra, u.email, u.nombre, u.telefono, u.direccion,
        (
            SELECT JSON_ARRAYAGG(
                JSON_OBJECT(
                    'id', r.id,
                    'nombre', r.nombre,
                    'permisos', (
                        SELECT JSON_ARRAYAGG(JSON_OBJECT('id', p2.id, 'nombre', p2.nombre))
                        FROM RolPermiso rp
                        JOIN Permiso p2 ON rp.permiso_id = p2.id
                        WHERE rp.rol_id = r.id
                    )
                )
            )
            FROM UsuarioRol ur
            JOIN Rol r ON ur.rol_id = r.id
            WHERE ur.usuario_id = u.id
        ) AS roles FROM Usuario u WHERE `+campo+` = ? GROUP BY u.id`
		fila := utils.BD.QueryRow(query, valor)
		
		var u UsuarioDetallado
		if err := sqlstruct.ScanStruct(fila, &u); err != nil {
				log.Error(err)
				return u,err
		}
		return u,nil
}

func Registrar(c echo.Context) error {
		var u Usuario
		log.Debug("registrar")
		if  err := c.Bind(&u); err != nil || len(u.Usuario) < 5 || !utils.REAlfaNum.MatchString(u.Usuario) || len(u.Contra) < 8 || !utils.REAlfaNum.MatchString(u.Contra) || !utils.REEmail.MatchString(u.Email) {
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"msj":utils.MsjResErrFormIncorrecto})
		}
		
		u.Contra, err = encriptar(u.Contra)
		if err == nil {
				id,err := sqlstruct.Alta(u)
				if err != nil{
						log.Debugf("ApiRes: %v", http.StatusInternalServerError)
						return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
				}
				log.Debugf("ApiRes: %v", http.StatusOK)
				return c.JSON(http.StatusOK, map[string]any{"msj":utils.MsjResAltaExito,"res":map[string]int64{"id":id}})
		} else {
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
		}
}

func Login(c echo.Context) error{
		var req LoginRequest
		if err := c.Bind(&req); err != nil {
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"msj":utils.MsjResErrFormIncorrecto})
		}
		usuario, err := getUsuario("u.usuario", req.Usuario)
		
		if err != nil{
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusNotFound)
				return c.JSON(http.StatusNotFound, map[string]string{"msj":utils.MsjResErrUsrNoExiste})
		}
		err = bcrypt.CompareHashAndPassword([]byte(usuario.Contra), []byte(req.Contra))
		
		if err != nil {
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"msj":utils.MsjResErrCredInvalidas})
		}
		
        access, refresh, err := generarJWT(usuario)
		
		var auxRoles []RolRes
		
		if usuario.Roles != nil {
				err = json.Unmarshal([]byte(*usuario.Roles),&auxRoles)
				if err != nil {
						log.Error(err)
						log.Debugf("ApiRes: %v", http.StatusInternalServerError)
						return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
				}
		}
		res := struct{				
				Id int `json:"id" form:"id"`
				Usuario string `json:"usuario" form:"usuario"`
				Email string `json:"email" form:"email"`
				Nombre *string `json:"nombre" form:"nombre"`
				Telefono *string `json:"telefono" form:"telefono"`
				Direccion *string `json:"direccion" form:"direccion"`
				Roles []RolRes `json:"roles" form:"roles"`
				RefreshToken string `json:"refresh_token" form:"refresh_token"`
				AccessToken string `json:"access_token" form:"access_token"`
				
		}{
				Id: usuario.Id,
				Usuario: usuario.Usuario,
				Direccion: usuario.Direccion,
				Nombre: usuario.Nombre,
				Telefono: usuario.Telefono,
				Email: usuario.Email,
				Roles: auxRoles,
				RefreshToken: refresh,
				AccessToken: access,
        }
		
		log.Debugf("ApiRes: %v", http.StatusOK)
		return c.JSON(http.StatusOK, map[string]any{"msj":utils.MsjResExito, "res":res})
}

func AltaUsuarioRol(c echo.Context) error {
		var aux map[string]any
		id := c.Param("id")
		c.Bind(&aux)
		if err = chequeoQueryData(aux,  []string{"rol_id"}); err != nil{
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"msj":utils.MsjResErrFormIncorrecto})
		}

		query := "INSERT INTO UsuarioRol (usuario_id,rol_id) VALUES (?, ?)"
		_, err := utils.BD.Exec(query, id, aux["rol_id"])
		if(err != nil){
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
		}
		return c.JSON(http.StatusOK, map[string]any{"msj":utils.MsjResModExito})
}

func BajaUsuarioRol(c echo.Context) error {
		var aux map[string]any
		id := c.Param("id")
		c.Bind(&aux)
		if err = chequeoQueryData(aux, []string{"rol_id"}); err != nil{
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"msj":utils.MsjResErrFormIncorrecto})
		}

		query := "DELETE FROM UsuarioRol WHERE usuario_id = ? AND rol_id = ?"
		_, err := utils.BD.Exec(query, id, aux["rol_id"])
		if(err != nil){
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
		}
		return c.JSON(http.StatusOK, map[string]string{"msj":utils.MsjResBajaExito})
}

func BuscarUsuario(c echo.Context) error {
		id := c.Param("id")
		u, err := getUsuario("u.id",id)
		if err != nil {
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
		}
		var aux []RolRes
		err = nil
		if u.Roles != nil {err = json.Unmarshal([]byte(*u.Roles),&aux)}		
		if err != nil {				
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
		}
		res := UsuarioDetalladoRes{
				Id: u.Id,
				Usuario: u.Usuario,
				Direccion: u.Direccion,
				Nombre: u.Nombre,
				Telefono: u.Telefono,
				Email: u.Email,
				Roles: aux,
        }
		return c.JSON(http.StatusOK, map[string]any{"msj":utils.MsjResExito, "datos":res})
}

func ListarUsuarios(c echo.Context) error {
		limite := c.QueryParam("limite")
		diferencia := c.QueryParam("diferencia")
		if limite == "" {
				limite = "10"
		}
		if diferencia == "" {
				diferencia = "0"
		}
		
		query := `SELECT u.id, u.usuario, u.contra, u.email, u.nombre, u.telefono, u.direccion, 
        (
            SELECT JSON_ARRAYAGG(
                JSON_OBJECT(
                    'id', r.id,
                    'nombre', r.nombre,
                    'permisos', (
                        SELECT JSON_ARRAYAGG(JSON_OBJECT('id', p2.id, 'nombre', p2.nombre))
                        FROM RolPermiso rp
                        JOIN Permiso p2 ON rp.permiso_id = p2.id
                        WHERE rp.rol_id = r.id
                    )
                )
            )
            FROM UsuarioRol ur
            JOIN Rol r ON ur.rol_id = r.id
            WHERE ur.usuario_id = u.id
        ) AS roles FROM Usuario u GROUP BY u.id LIMIT ? OFFSET ?`
		
		filas, err := utils.BD.Query(query,limite,diferencia)
		var u UsuarioDetallado
		usuarios := [] any {}
		usuarios, err = sqlstruct.ScanSlice(filas, u)
		if err != nil {
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
		}

		var res []UsuarioDetalladoRes
		var auxRoles []RolRes
		for i := range usuarios {
				auxPuntero := usuarios[i].(*UsuarioDetallado)
				auxUsuario := *auxPuntero
				auxRoles = nil
				err = nil
				if auxUsuario.Roles != nil{err = json.Unmarshal([]byte(*auxUsuario.Roles), &auxRoles)}
				if err != nil {
						log.Error(err)
						return c.JSON(http.StatusInternalServerError, map[string]string{"msj": utils.MsjResErrInterno})
				}
				resindex := UsuarioDetalladoRes{
						Id: auxUsuario.Id,
						Usuario: auxUsuario.Usuario,
						Direccion: auxUsuario.Direccion,
						Nombre: auxUsuario.Nombre,
						Telefono: auxUsuario.Telefono,
						Email: auxUsuario.Email,
						Roles: auxRoles,
				}
				res = append(res,resindex)
		}
		return c.JSON(http.StatusOK, map[string]any{"msj":utils.MsjResExito,"res":res})
}

func ModificarUsuario(c echo.Context) error {
		var u Usuario
		log.Debug("ModificarUsuario")
		id := c.Param("id")
		if  err := c.Bind(&u); err != nil || len(u.Usuario) < 5 || !utils.REAlfaNum.MatchString(u.Usuario) || len(u.Contra) < 8 || !utils.REAlfaNum.MatchString(u.Contra) || !utils.REEmail.MatchString(u.Email) {
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"msj":utils.MsjResErrFormIncorrecto})
		}
		
		u.Contra, err = encriptar(u.Contra)
		if err == nil {
				if err = sqlstruct.Modificar(u,id); err != nil{
						log.Debugf("ApiRes: %v", http.StatusInternalServerError)
						return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
				}
				log.Debugf("ApiRes: %v", http.StatusOK)
				return c.JSON(http.StatusOK, map[string]string{"msj": utils.MsjResModExito})
		} else {
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
		}
}

func BajaUsuario(c echo.Context) error {
		log.Debug("BajaUsuario")
		id := c.Param("id")
		
		if err = sqlstruct.Baja("Usuario", id); err == nil {
				log.Debugf("ApiRes: %v", http.StatusOK)
				return c.JSON(http.StatusOK, map[string]string{"msj": utils.MsjResBajaExito})
		} else {
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
		}
}
