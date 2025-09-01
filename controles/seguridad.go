package controles

import (
		"encoding/json"
		"fran/sqlstruct"
		"fran/utils"
		"net/http"
		"strconv"
		"time"
		_ "github.com/go-sql-driver/mysql"
		"github.com/golang-jwt/jwt/v5"
		"github.com/labstack/echo/v4"
		log "github.com/sirupsen/logrus"
		"golang.org/x/crypto/bcrypt"
)

type Sesion struct {
		Id int `json:"id" form:"id"` 
		Usuario_id int `json:"usuario_id" form:"usuario_id"`
		Refresh_token string `json:"refresh_token" form:"refresh_token"`
		Creado time.Time `json:"creado" form:"creado"`
		Expira time.Time `json:"expira" form:"expira"`
		Activo bool `json:"activo" form:"activo"`
}

func diferenciaFechas(fecha1, fecha2 time.Time) (dias, horas float64) {
		diferencia := fecha2.Sub(fecha1)
		horas = diferencia.Hours()
		dias = horas / 24
		return dias, horas
}

func desactivarSesion(usuario_id int, refresh_token string) error {
		query := "UPDATE Sesion SET activo = false WHERE usuario_id = ? AND refresh_token = ?"
		_, err := utils.BD.Exec(query, usuario_id, refresh_token)
		if err != nil {
				log.Error(err)
				return err
		}
		return nil
}

func encriptar(contra string) (string, error){
		bytes_hash, err := bcrypt.GenerateFromPassword([]byte(contra), 15)
		return string(bytes_hash), err
}

func getSesion(usuario_id int, refresh_token string) (res Sesion, err error) {
		log.Debugf("usuario: %d, token: %s", usuario_id, refresh_token)
		query := "SELECT * FROM Sesion WHERE usuario_id = ? AND refresh_token = ?"
		fila := utils.BD.QueryRow(query, usuario_id, refresh_token)
		
		if err := sqlstruct.ScanStruct(fila, &res); err != nil  {
				log.Error(err)
				return res, err
		}
		return res, nil
}

func generarJWTAcceso(usuario UsuarioDetallado) (access string, err error) {
		var roles string
		if(usuario.Roles != nil){roles = *usuario.Roles}
		accclaims := jwt.MapClaims{
				"usuario": usuario.Id,
				"tipo": "access",
				"roles": roles,
				"exp": time.Now().Add(15 * time.Minute).Unix(),
		}
		at := jwt.NewWithClaims(jwt.SigningMethodHS256, accclaims)
		access, err = at.SignedString(utils.JWTSecret)
		return
}

func generarJWT(usuario UsuarioDetallado) (access string, refresh string, err error) {
		access, err = generarJWTAcceso(usuario)
		refreshClaims := jwt.MapClaims{
				"usuario": usuario.Id,
				"tipo": "refresh",
				"exp": time.Now().Add(7 * 24 * time.Hour).Unix(),
		}
		rt := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
		refresh, err = rt.SignedString(utils.JWTSecret)
		aux := Sesion{
				Usuario_id : usuario.Id,
				Refresh_token : refresh,
				Creado : time.Now(),
				Expira : time.Now().AddDate(0,0,7),
				Activo : true,
		}
		sqlstruct.Alta(aux)
		return
}

func RefreshToken(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(jwt.MapClaims)
		tipo := claims["tipo"].(string)
		if tipo != "refresh" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"msj":utils.MsjResErrCredInvalidas})
		}
		refresh := user.Raw
		usuario_id := int(claims["usuario"].(float64))
		sesion, err := getSesion(usuario_id, refresh)
		
		if err != nil || !sesion.Activo || time.Now().After(sesion.Expira){
				if sesion.Activo && time.Now().After(sesion.Expira) {
						desactivarSesion(sesion.Usuario_id, sesion.Refresh_token)
				}
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusNotFound)
				return c.JSON(http.StatusNotFound, map[string]string{"msj":utils.MsjResErrCredInvalidas})
		}	
		
		usuario, err := getUsuario("u.id", strconv.Itoa(usuario_id) )
		
		if err != nil{
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusNotFound)
				return c.JSON(http.StatusNotFound, map[string]string{"msj":utils.MsjResErrCredInvalidas})
		}

		dias, horas := diferenciaFechas(time.Now(), sesion.Expira)
		log.Debugf("Faltan %.2f horas y %.2f dias para que expire el token", horas, dias)
		refrescar := dias < 1
		var access string
		var aux []RolRes
		if refrescar {
				if err := desactivarSesion(sesion.Usuario_id, sesion.Refresh_token); err != nil {
						log.Error(err)
						return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
				}
				access, refresh, err = generarJWT(usuario)
				if err != nil {				
						log.Error(err)
						log.Debugf("ApiRes: %v", http.StatusInternalServerError)
						return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
				}
		} else {
				access, err = generarJWTAcceso(usuario)
				if err != nil {
						log.Error(err)
						return c.JSON(http.StatusInternalServerError, map[string]string{"msj": utils.MsjResErrInterno})
				}
		}
		err = json.Unmarshal([]byte(*usuario.Roles),&aux)
		if err != nil {
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
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
				Roles: aux,
				RefreshToken: refresh,
				AccessToken: access,
        }
		log.Debugf("ApiRes: %v", http.StatusOK)
		return c.JSON(http.StatusOK, map[string]any{"msj":utils.MsjResModExito, "res": res})
}

func FiltroCheck(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
		claims := user.Claims.(jwt.MapClaims)
		usuario := claims["usuario"].(string)
		roles := claims["roles"].(string)
		return c.JSON(http.StatusOK, map[string]any{
				"msj": "Filtro Check",
				"res": map[string]string{
						"usuario": usuario,
						"roles": roles,
				},})
}

func FiltroSuperAdmin(next echo.HandlerFunc) echo.HandlerFunc {
		return func (c echo.Context) error {
				user := c.Get("user").(*jwt.Token)
				claims := user.Claims.(jwt.MapClaims)
				tipo := claims["tipo"].(string)
				if tipo != "access" {
						return c.JSON(http.StatusUnauthorized, map[string]string{"msj":utils.MsjResErrCredInvalidas})
				}
				
				rolesAux := claims["roles"].(string)
				log.Debug(rolesAux)
				var roles []RolRes
				err = json.Unmarshal([]byte(rolesAux),&roles)
				if err != nil {						
						log.Error(err)
						log.Debugf("ApiRes: %v", http.StatusInternalServerError)
						return c.JSON(http.StatusInternalServerError, map[string]string{"msj":utils.MsjResErrInterno})
				}
				for _, r := range roles {
						if r.Nombre == "ADMIN"{
								return next(c)
						}
				}
				return c.JSON(http.StatusUnauthorized, map[string]string{"msj":utils.MsjResErrNoAutorizado})
		}
}
