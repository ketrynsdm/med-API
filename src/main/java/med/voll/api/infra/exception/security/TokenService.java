package med.voll.api.infra.exception.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import io.jsonwebtoken.*;
import med.voll.api.domain.usuario.Usuario;
import med.voll.api.utils.DateTimeUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.security.Key;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class TokenService {
    @Value("${api.security.token.secret}")
    private String secret;

    @Value("${api.security.token.expiration}")
    private Long jwtExpirationMs;

    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    public String gerarToken(Usuario usuario) {
        try {

            String token = "Bearer " + Jwts.builder()
                    .setSubject(usuario.getLogin())
                    .setIssuedAt(DateTimeUtils.now())
                    .setExpiration(new Date(DateTimeUtils.now().getTime() + jwtExpirationMs))
                    .signWith(signatureAlgorithm, getSecretyKey())
                    .compact();

            return token;
        } catch (JWTCreationException exception){
            throw new RuntimeException("erro ao gerrar token jwt", exception);
        }
    }
    private Key getSecretyKey(){
        System.out.println(secret);

        byte[] apiKeySecretBytes = Base64.getEncoder().encode(secret.getBytes(StandardCharsets.UTF_8));
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        return signingKey;
    }

    /**
     * Obtém as informações armazendas no token
     * @param token
     * @return
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder().setSigningKey(getSecretyKey()).build().parseClaimsJws(token).getBody();
    }

    /**
     * Obtém uma info específica armazenada no token
     * @param token
     * @param claimsResolver
     * @param <T>
     * @return
     */
    private <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Obtém uma info específica armazenada no token
     * @return
     */
    private <T> T getClaimFromToken(String token, String key, Class<T> type) {
        final Claims claims = getAllClaimsFromToken(token);
        return claims.get(key, type);
    }

    /**
     * Obtém a data/hora de expiração do token
     * @param token
     * @return
     */
    private Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * Verifica se o token expirou
     * @param token
     * @return
     */
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(DateTimeUtils.now());
    }

    /**
     * Obtém o nome de usuário no token
     * @param token
     * @return
     */
    public String getUserNameFromJwtToken(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }

    /**
     * Verifica se o token recebido na sessão é válido
     * @param authToken
     * @return
     */
    public boolean validateJwtToken(String authToken) {
        try {
            //Valida a estrutura do token
            if(getAllClaimsFromToken(authToken)==null) throw new AccessDeniedException("Usuário não autenticado!");

            //Valida a data de validade
            if(isTokenExpired(authToken)) throw new AccessDeniedException("Usuário não autenticado!");

            //Se estiver tudo ok, permite o acesso
            return true;
        } catch (Exception e){
            System.out.println("Invalid JWT token: "+ e.getMessage());
        }

        return false;
    }

}
