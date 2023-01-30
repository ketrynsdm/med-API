package med.voll.api.utils;

import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class DateTimeUtils {

    /**
     * Timestamp atual
     * @return
     */
    public static Date now(){
        return Calendar.getInstance(timezone()).getTime();
    }

    /**
     * Timezone do sistema
     * @return
     */
    public static TimeZone timezone() {
        return TimeZone.getTimeZone("America/Sao_Paulo");
    }

}
