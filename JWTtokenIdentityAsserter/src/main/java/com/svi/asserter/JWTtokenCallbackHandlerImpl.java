package com.svi.asserter;

import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/*package*/ class JWTtokenCallbackHandlerImpl implements CallbackHandler
{
    private String userName; // the name of the user from the identity assertion token
    private List<String> groupsList;

    /*package*/ JWTtokenCallbackHandlerImpl(String user, List<String> grpList)
    {
        userName = user;
        groupsList = grpList;
    }

    /*package*/ JWTtokenCallbackHandlerImpl(String user)
    {
        userName = user;
    }

    public void handle(Callback[] callbacks) throws UnsupportedCallbackException
    {
        // loop over the callbacks
        for (int i = 0; i < callbacks.length; i++) {

            Callback callback = callbacks[i];

            // we only handle NameCallbacks
            if (!(callback instanceof NameCallback)) {
                throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
            }

            // send the user name to the name callback:
            NameCallback nameCallback = (NameCallback)callback;
            nameCallback.setName(userName);
        }
    }
    
    public List<String> getGroups() {
        return groupsList;
    }
}
