package controles

import (
		"net/http"
		"fran/sqlstruct"
		"fran/utils"
		"encoding/json"
		"github.com/labstack/echo/v4"
		log "github.com/sirupsen/logrus"
		_ "github.com/go-sql-driver/mysql"
)
type RolRes struct {		
		Id int `json:"id" form:"id"`
		Nombre string `json:"nombre" form:"nombre"`
		Permisos []Permiso `json:"permisos" form:"permisos"`
}

type RolAux struct {
		Id int `json:"id" form:"id"`
		Nombre string `json:"rol" form:"rol"`
		Permisos string `json:"permisos" form:"permisos"`
}

type Permiso struct {
		Id int `json:"id" form:"id"`
		Nombre string `json:"nombre" form:"nombre"`
}

func BuscarRol(c echo.Context) error {
		id := c.Param("id")
		log.Debug("BuscarRol")
		query := "SELECT r.id, r.nombre AS rol, JSON_ARRAYAGG(JSON_OBJECT('id', p.id,'nombre', p.nombre)) AS permisos FROM Rol r LEFT JOIN RolPermiso rp ON r.id = rp.rol_id LEFT JOIN Permiso p ON rp.permiso_id = p.id WHERE r.id = ?"
		fila := utils.BD.QueryRow(query, id)

		var rol RolAux
		
		if err := sqlstruct.ScanStruct(fila, &rol); err != nil  {
				log.Errorf("BuscarRol: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno} )
		}
		
		var auxiliar []Permiso
		err := json.Unmarshal([]byte(rol.Permisos), &auxiliar)
		if err != nil {
				log.Errorf("BuscarRol: %v",err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"msj": utils.MsjResErrInterno})
		}		
		if auxiliar[0].Id == 0 && auxiliar[0].Nombre == "" {
				auxiliar = nil
		}
		res := RolRes{
				Id: rol.Id,
				Nombre: rol.Nombre,
				Permisos: auxiliar,
		}		
		return c.JSON(http.StatusOK, map[string]any{"mensaje":utils.MsjResExito, "datos":res})
}

func BuscarPermiso(c echo.Context) error {
		id := c.Param("id")		
		log.Debug("BuscarPermiso")
		query := "SELECT * FROM Permiso WHERE id = ?"
		fila := utils.BD.QueryRow(query, id)

		var res Permiso
		
		if err := sqlstruct.ScanStruct(fila, &res); err != nil  {
				log.Errorf("BuscarPermiso: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno} )
		}
		return c.JSON(http.StatusOK, map[string]any{"mensaje":utils.MsjResExito, "datos":res})
}

func ListarPermisos(c echo.Context) error {
		limite := c.QueryParam("limite")
		diferencia := c.QueryParam("diferencia")
		log.Debugf("ListarPermisos: limite %v diferencia %v", limite, diferencia)
		if limite == "" {
				limite = "10"
		}
		if diferencia == "" {
				diferencia = "0"
		}
		
		query := "SELECT * FROM Permiso ORDER BY id LIMIT ? OFFSET ?"
		
		filas, err := utils.BD.Query(query,limite,diferencia)
		var aux Permiso
		res, err := sqlstruct.ScanSlice(filas, aux)
		if err != nil {
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}
		return c.JSON(http.StatusOK, map[string]any{"mensaje":utils.MsjResExito, "datos":res})
}

func ListarRoles(c echo.Context) error {
		limite := c.QueryParam("limite")
		diferencia := c.QueryParam("diferencia")
		log.Debugf("ListarRoles: limite %v diferencia %v", limite, diferencia)
		if limite == "" {
				limite = "10"
		}
		if diferencia == "" {
				diferencia = "0"
		}
		
		query := "SELECT r.id, r.nombre AS rol, JSON_ARRAYAGG(JSON_OBJECT('id', p.id,'nombre', p.nombre)) AS permisos FROM Rol r LEFT JOIN RolPermiso rp ON r.id = rp.rol_id LEFT JOIN Permiso p ON rp.permiso_id = p.id GROUP BY r.id LIMIT ? OFFSET ?"
		
		filas, err := utils.BD.Query(query,limite,diferencia)
		var rol RolAux
		roles := [] any {}
		roles, err = sqlstruct.ScanSlice(filas, rol)
		if err != nil {
				log.Error(err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}
		var res []RolRes
		
		var auxPermisos []Permiso
		for i := range roles {
				auxPuntero := roles[i].(*RolAux)
				auxRol := *auxPuntero
				auxPermisos = nil
				err := json.Unmarshal([]byte(auxRol.Permisos), &auxPermisos)
				if err != nil {
						log.Errorf("BuscarRol: %v",err)
						return c.JSON(http.StatusInternalServerError, map[string]string{"msj": utils.MsjResErrInterno})
				}
				
				if auxPermisos[0].Id == 0 && auxPermisos[0].Nombre == "" {
						auxPermisos = nil
				}
				resindex := RolRes{
						Id: auxRol.Id,
						Nombre: auxRol.Nombre,
						Permisos: auxPermisos,
				}
				res = append(res,resindex)
		}
		
		return c.JSON(http.StatusOK, map[string]any{"mensaje":utils.MsjResExito, "datos":res})
}

func BajaRolPermiso(c echo.Context) error {
		var aux map[string]any
		id := c.Param("id")
		c.Bind(&aux)
		if err = chequeoQueryData(aux,  []string{"permiso_id"}); err != nil{
				log.Debugf("%s\nApiRes: %v", err, http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":utils.MsjResErrFormIncorrecto})
		}

		query := "DELETE FROM RolPermiso WHERE rol_id = ? AND permiso_id = ?"
		_, err := utils.BD.Exec(query, id, aux["permiso_id"])
		if(err != nil){
				log.Errorf("EliminarRolPermiso: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}
		return c.JSON(http.StatusOK, map[string]string{"mensaje":utils.MsjResBajaExito})
}


func AltaRolPermiso(c echo.Context) error {
		var aux map[string]any
		id := c.Param("id")
		c.Bind(&aux)
		if err = chequeoQueryData(aux,  []string{"permiso_id"}); err != nil{
				log.Debugf("%s\nApiRes: %v", err, http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":utils.MsjResErrFormIncorrecto})
		}

		query := "INSERT INTO RolPermiso (rol_id,permiso_id) VALUES (?, ?)"
		_, err := utils.BD.Exec(query, id, aux["permiso_id"])
		if(err != nil){
				log.Errorf("AltaRolPermiso: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}		
		return c.JSON(http.StatusOK, map[string]string{"mensaje":utils.MsjResModExito})
}

func AltaRolOPermiso(c echo.Context) error {
		tabla := utils.IndiceMayuscula(c.Path()[3:],0)
		
		var aux map[string]string
		c.Bind(&aux)
		if  aux["nombre"] == ""  {
				log.Debugf("ApiRes: %v", http.StatusBadRequest)
				return c.JSON(http.StatusBadRequest, map[string]string{"mensaje":utils.MsjResErrFormIncorrecto})
		}
		query := "INSERT INTO "+tabla+" (nombre) VALUES (?)"
		res, err := utils.BD.Exec(query, aux["nombre"])
		if(err != nil){
				log.Errorf("AltaRolOPermiso: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}
		resid, err :=  res.LastInsertId()
		if(err != nil){
				log.Errorf("AltaRolOPermiso: %v",err)
				log.Debugf("ApiRes: %v", http.StatusInternalServerError)
				return c.JSON(http.StatusInternalServerError, map[string]string{"mensaje":utils.MsjResErrInterno})
		}
		return c.JSON(http.StatusOK, map[string]any{"mensaje":utils.MsjResModExito, "datos":map[string]int64{"id":resid}})
}
