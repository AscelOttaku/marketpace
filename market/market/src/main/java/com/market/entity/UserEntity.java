package com.market.entity;

import com.market.enums.UserRole;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@Entity
@Table(name = "users")
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    @Column(nullable = false)
    String name;

    @Column(nullable = false)
    String surname;

    String patronymic;

    @Column(nullable = false, unique = true)
    String msisdn;

    @Column(nullable = false, unique = true)
    String email;

    String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    UserRole role;
}
