package sqlstruct
import 	(
		"strings"	
		"fmt"		
		log "github.com/sirupsen/logrus"
		"reflect"
		"errors"
		"database/sql"
		"fran/utils"
)

var err error = nil

func validarStruct(s any) (reflect.Type, error) {
		t := reflect.TypeOf(s)
		if t.Kind() == reflect.Ptr {
				t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
				return nil, errors.New("tipo debe ser un struct o puntero a struct")
		}

		for i := 0; i < t.NumField(); i++ {
				if t.Field(i).PkgPath != "" {
						return nil, errors.New("campo "+t.Field(i).Name+" no es exportado")
				}
		}
		return t, nil
}

func StructAstring(s any) (tabla string, campos []string, valores []any, error error) {
		t, err := validarStruct(s)
		if err != nil {
				return "", nil, nil, err
		}

		v := reflect.ValueOf(s)
		if v.Kind() == reflect.Ptr {
				v = v.Elem()
		}
		
		tabla = t.Name()
		campos = make([]string, t.NumField())
		valores = make([]any, t.NumField())	
		for i := range campos {
				campos[i] = strings.ToLower(t.Field(i).Name)
				f := v.Field(i)
				if f.Kind() == reflect.Ptr {
						if f.IsNil() {
								valores[i] = nil
						} else {
								valores[i] = f.Elem().Interface()
						}
				} else {
						valores[i] = f.Interface()
				}
		}
		return
}

func ScanStruct(row *sql.Row, dest any) error {
		v := reflect.ValueOf(dest)
		if v.Kind() != reflect.Ptr || v.IsNil() {
				return errors.New("dest debe ser un struct")
		}
		v = v.Elem()
		if v.Kind() != reflect.Struct {
				return errors.New("dest debe ser un struct")
		}
		campos := make([]any, v.NumField())
		for i := range campos {
				campos[i] = v.Field(i).Addr().Interface()
		}
		return row.Scan(campos...)
}

func ScanSlice(rows *sql.Rows, tipo any) (retorno []any, err error) {
		defer rows.Close()
		t, err := validarStruct(tipo)
		if err != nil {
				return nil, err
		}

		retorno = []any{}
		for rows.Next() {
				ptr := reflect.New(t)      // *T
				elem := ptr.Elem()         // T
        
				campos := make([]any, elem.NumField())
				for i := range campos {
						campos[i] = elem.Field(i).Addr().Interface() //campos[i]=*T.campoi
				}
		
				if err := rows.Scan(campos...); err != nil {
						return nil, err
				}
				retorno = append(retorno, ptr.Interface())
		}
		if err := rows.Err(); err != nil {
				return nil, err
		}    
		return retorno, nil
}

func Modificar(u any, id string) error{
		log.Debugf("modificar: %v", u)
		tabla, campos, valores, err := StructAstring(u)
		log.Debugf("tabla: %v", tabla)
		log.Debugf("campos: %v", campos)
		log.Debugf("valores: %v", valores)
		if err != nil {
				log.Error(err)
				return err
		}
		
		var auxiliar []string
		for i := range campos {
				auxiliar = append(auxiliar, fmt.Sprintf("%s = ?", campos[i]))
		}
		result := strings.Join(auxiliar, ", ")
	
		query := fmt.Sprintf("UPDATE %s SET %s WHERE id = ?", tabla, result)
		valores = append(valores, id)
		_, err = utils.BD.Exec(query, valores...)
		if(err != nil){
				log.Error(err)
				return err
		}
		return nil
}

func Baja(tabla string, id string) error {
		log.Debugf("alta: %s", id)
		query := fmt.Sprintf("DELETE FROM %s WHERE id = ?", tabla)
		_, err = utils.BD.Exec(query, id)
		if(err != nil){
				log.Error(err)
				return err
		}
		return nil
}

func Alta(u any) (id int64, err error){
		log.Debugf("alta: %v", u)
		tabla, campos, valores, err := StructAstring(u)
		log.Debugf("tabla: %v", tabla)
		log.Debugf("campos: %v", campos)
		log.Debugf("valores: %v", valores)
		if err != nil {
				log.Error(err)
				return -1, err
		}
		placeholders := strings.Repeat("?,", len(campos))
		camposStr := strings.Join(campos, ",")
		placeholders = placeholders[:len(placeholders)-1]
	
		query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tabla, camposStr, placeholders)
		res, err := utils.BD.Exec(query, valores...)
		if(err != nil){
				log.Error(err)
				return -1, err
		}
		resid, err :=  res.LastInsertId()
		if(err != nil){
				log.Error(err)
				return -1, err
		}
		return resid, nil
}
