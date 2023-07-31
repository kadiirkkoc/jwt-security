package com.kadir.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "045871d0ab8dd1ed586866dc01d43c5c1db4771f2c1d89d778b45e982142bff6";

    public String extractUsername(String token){
        return extractClaim(token,Claims::getSubject);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }
    public String generateToken(
            Map<String , Object> extraClaims,//A map of additional claims that you want to include in the generated JWT.
                                             // These claims represent additional information related to the user or any custom data you want to associate with the token.
            UserDetails userDetails //An instance of UserDetails, which represents the authenticated user's information, such as username, password, and authorities.
    ){
        return Jwts
                .builder()//Creates a JWT builder object to build the JWT.
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); //Builds the final JWT and returns it as a compact string.
    }

    //user info which logged in with mail and password in the token compare with*******
    public boolean isTokenValid(String token,UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllCalims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllCalims(String token){
        return Jwts
                .parserBuilder() //Creates a JWT parser object to process the JWT.
                .setSigningKey(getSignInKey()) //Specifies the signing key used for JWT verification. The getSignInKey() method can be called to obtain this key. JWT verification ensures that the transported data is trustworthy and hasn't been altered.
                .build() //Completes the configuration of the JWT parser object
                .parseClaimsJws(token) //Splits the provided JWT into its components and extracts the data within it.
                .getBody(); // Returns the "body" section (claims) of the JWT. The "body" of the JWT is a JSON object that carries user information and other authorities.
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
