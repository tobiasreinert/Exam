package cache;

import controllers.UserController;
import java.util.ArrayList;
import model.User;
import utils.Config;

//TODO: Build this cache and use it
public class UserCache {


        // List of orders
        private ArrayList<User> users;

        // Time cache should live
        private long ttl;

        // Sets when the cache has been created
        private long created;

        public UserCache() {
            this.ttl = Config.getUserTtl();
        }

        public ArrayList<User> getUsers(Boolean forceUpdate) {

            // If we whis to clear cache, we can set force update.
            // Otherwise we look at the age of the cache and figure out if we should update.
            // If the list is empty we also check for new orders
            if (forceUpdate
                    || ((this.created + this.ttl) <= (System.currentTimeMillis() / 1000L))
                    || this.users == null) {

                // Get orders from controller, since we wish to update.
                ArrayList<User> users = UserController.getUsers();

                // Set orders for the instance and set created timestamp
                this.users = users;
                this.created = System.currentTimeMillis() / 1000L;
            }

            // Return the documents
            return this.users;
        }
    }



