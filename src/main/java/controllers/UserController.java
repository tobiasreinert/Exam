package controllers;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;

import cache.UserCache;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import model.User;
import utils.Hashing;
import utils.Log;

public class UserController {

  private static DatabaseController dbCon;
  //private static Hashing hashing;

  //String token = null;

  public UserController() {
    dbCon = new DatabaseController();
  }

  public static User getUser(int id) {

    // Check for connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    UserCache userCache = new UserCache();
    userCache.getUsers(true);

    // Build the query for DB
    String sql = "SELECT * FROM user where id=" + id;

    // Actually do the query
    ResultSet rs = dbCon.query(sql);
    User user = null;

    try {
      // Get first object, since we only have one
      if (rs.next()) {
        user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"),
                        rs.getLong("created_at"));


        // return the create object
        return user;
      } else {
        System.out.println("No user found");
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return null
    return user;
  }

  /**
   * Get all users in database
   *
   * @return
   */
  public static ArrayList<User> getUsers() {

    // Check for DB connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Build SQL
    String sql = "SELECT * FROM user";


    // Do the query and initialyze an empty list for use if we don't get results
    ResultSet rs = dbCon.query(sql);
    ArrayList<User> users = new ArrayList<User>();

    try {
      // Loop through DB Data
      while (rs.next()) {
        User user =
                new User(
                        rs.getInt("id"),
                        rs.getString("first_name"),
                        rs.getString("last_name"),
                        rs.getString("password"),
                        rs.getString("email"),
                        rs.getLong("created_at"));

        // Add element to list
        users.add(user);
      }
    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    // Return the list of users
    return users;
  }

  public static User createUser(User user) {

    Hashing hashing = new Hashing();

    // Write in log that we've reach this step
    Log.writeLog(UserController.class.getName(), user, "Actually creating a user in DB", 0);

    // Set creation time for user.
    user.setCreatedTime(System.currentTimeMillis() / 1000L);

    // Check for DB Connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    // Insert the user in the DB
    // TODO: Hash the user password before saving it. (skal hashes)
    int userID = dbCon.insert(
            "INSERT INTO user(first_name, last_name, password, email, created_at) VALUES('"
                    + user.getFirstname()
                    + "', '"
                    + user.getLastname()
                    + "', '"
                    + user.getPassword()
                    + "', '"
                    + user.getEmail()
                    + "', "
                    + user.getCreatedTime()
                    + ")");

    if (userID != 0) {
      //Update the userid of the user before returning
      user.setId(userID);
    } else {
      // Return null if user has not been inserted into database
      return null;
    }

    // Return user
    return user;
  }


  public String login(User user) {

    Hashing hashing = new Hashing();

    Log.writeLog(UserController.class.getName(), user, "Login", 0);

    // Check for connection
    if (dbCon == null) {
      dbCon = new DatabaseController();
    }


    // Build the query for DB
    // String sql = "SELECT * FROM user WHERE email= '" + user.getEmail() + "' AND password='" + Hashing.sha(user.getPassword()) + "'";
    String sql = "SELECT * FROM user WHERE email='" + user.getEmail() + "' AND password = '" + Hashing.sha(user.getPassword()) + "'";
    // select from user wnere id = 1;
    // select from user where email = 'test@example.com' AND

    ResultSet rs = dbCon.query(sql);
    User loginUser = null;
    String token = null;
    //hashing.setLoginSalt(String.valueOf(System.currentTimeMillis() / 1000L));

    try {
      // Get first object, since we only have one
      if (rs.next()) {
        loginUser = new User(
                rs.getInt("id"),
                rs.getString("first_name"),
                rs.getString("last_name"),
                rs.getString("password"),
                rs.getString("email"),
                rs.getLong("created_at"));

        try {
          Algorithm algorithm = Algorithm.HMAC256("secret");
          token = JWT.create()
                  .withIssuer("auth0").withClaim("userId", loginUser.id).withClaim("createdAt", loginUser.getCreatedTime())
                  .sign(algorithm);
        } catch (JWTCreationException exception) {
          //Invalid Signing configuration / Couldn't convert Claims.
        }

        Log.writeLog(UserController.class.getName(), user, "User actually logged in", 0);
        // return hashing.hashTokenWithSalt(token);     Hashet token
        return token;
      } else {
        // System.out.println("Wrong username or password");
        System.out.println("Could not find user");

      }


    } catch (SQLException ex) {
      System.out.println(ex.getMessage());
    }

    return null;
  }

  public static boolean delete(String token) {

    DecodedJWT jwt = null;
    try {
      jwt = JWT.decode(token);
    } catch (JWTDecodeException exception) {

    }

    int id = jwt.getClaim("userId").asInt();

    Log.writeLog(UserController.class.getName(), null, "Deleting user with id: " + id, 0);

    String sql = "DELETE from user where id =" + id;

    if (dbCon == null) {
      dbCon = new DatabaseController();
    }

    int i = dbCon.deleteUser(sql);

    if (i == 1) {
      Log.writeLog(UserController.class.getName(), null, "User was actually deleted with id: " + id + " and " + i + " rows were/was affected", 0);
      return true;
    } else {
      return false;
    }

  }

}







