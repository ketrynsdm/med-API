package med.voll.api.infra.exception.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Log4j2
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    /**
     * Lança exceção de acesso negado ao endpoint requisitado quando um usuário não autenticado tenta acessar o endpoint
     * @throws IOException
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, AccessDeniedException {
        String msg = authException.getMessage();

        if(msg.equalsIgnoreCase("Full authentication is required to access this resource")){
            msg = "Acesso negado!";
        }else if(msg.equalsIgnoreCase("Bad credentials")){
            msg = "Acesso negado!";
        }

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        new ObjectMapper().writeValue(response.getOutputStream(), msg);//new WebResponse(HttpStatus.UNAUTHORIZED, msg)
    }

}
