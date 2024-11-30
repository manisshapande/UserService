package com.example.userservice.services;

import com.example.userservice.models.Token;
import com.example.userservice.models.User;
import com.example.userservice.repos.TokenRepo;
import com.example.userservice.repos.UserRepo;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private TokenRepo tokenRepo;
    private UserRepo userRepo;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserRepo userRepo, BCryptPasswordEncoder bCryptPasswordEncoder, TokenRepo tokenRepo) {
        this.userRepo = userRepo;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.tokenRepo = tokenRepo;
    }

    public User signUp(String name, String email, String password) {

        //Add Validation
        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setHashedPassword(bCryptPasswordEncoder.encode(password));

        return userRepo.save(user);
    }

    public Token login(String email, String password) {
        Optional<User> optionalUser = userRepo.findByEmail(email);
        if (optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User with Email " + email + " not found");
        }
        User user = optionalUser.get();
        if (!bCryptPasswordEncoder.matches(password, user.getHashedPassword())) {
            throw new BadCredentialsException("Wrong password");
        }
        Token token = generateToken(user);
        return tokenRepo.save(token);

    }

    private Token generateToken(User user) {
        Token token = new Token();
        token.setValue(RandomStringUtils.randomAlphanumeric(10));
        token.setUser(user);
        token.setExpiryAt(System.currentTimeMillis()+3600000);
        return token;

    }

    public User validateToken(String token) {
        /*
         A token is valid if
         1. token exist in db
         2. token has not expired
         3. token has not marked as deleted
         */
        Optional<Token> tokenResult = tokenRepo
                .findByValueAndIsDeletedAndExpiryAtGreaterThan(token, false, System.currentTimeMillis());
        if (tokenResult.isEmpty()) {
            //throw new BadCredentialsException("Invalid token");
            return null;
        }
        return tokenResult.get().getUser();
    }
}
