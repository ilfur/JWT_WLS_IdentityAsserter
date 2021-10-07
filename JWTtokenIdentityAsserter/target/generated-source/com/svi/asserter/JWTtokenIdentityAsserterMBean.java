package com.svi.asserter;


import javax.management.*;
import weblogic.management.commo.RequiredModelMBeanWrapper;



/**
 * No description provided.
 * @root JWTtokenIdentityAsserter
 * @customizer com.svi.asserter.JWTtokenIdentityAsserterImpl(new RequiredModelMBeanWrapper(this))
 * @dynamic false

 */
public interface JWTtokenIdentityAsserterMBean extends weblogic.management.commo.StandardInterface,weblogic.descriptor.DescriptorBean, weblogic.management.security.authentication.IdentityAsserterMBean {
                
        


        /**
         * No description provided.

         * @preprocessor weblogic.management.configuration.LegalHelper.checkClassName(value)
         * @default "com.svi.asserter.JWTtokenIdentityAsserterProviderImpl"
         * @dynamic false
         * @non-configurable
         * @validatePropertyDeclaration false

         * @preserveWhiteSpace
         */
        public java.lang.String getProviderClassName ();


        
        


        /**
         * No description provided.

         * @default "WebLogic JWT Token Identity Asserter Provider"
         * @dynamic false
         * @non-configurable
         * @validatePropertyDeclaration false

         * @preserveWhiteSpace
         */
        public java.lang.String getDescription ();


        
        


        /**
         * No description provided.

         * @default "1.0"
         * @dynamic false
         * @non-configurable
         * @validatePropertyDeclaration false

         * @preserveWhiteSpace
         */
        public java.lang.String getVersion ();


        
        


        /**
         * No description provided.

         * @default "Authorization"
         * @dynamic false
         * @non-configurable
         * @validatePropertyDeclaration false

         * @preserveWhiteSpace
         */
        public java.lang.String[] getSupportedTypes ();


        
        


        /**
         * No description provided.

         * @default "Authorization"
         * @dynamic false

         * @preserveWhiteSpace
         */
        public java.lang.String[] getActiveTypes ();


        /**
         * No description provided.

         * @default "Authorization"
         * @dynamic false

         * @param newValue - new value for attribute ActiveTypes
         * @exception InvalidAttributeValueException
         * @preserveWhiteSpace
         */
        public void setActiveTypes (java.lang.String[] newValue)
                throws InvalidAttributeValueException;


        
        


        /**
         * No description provided.

         * @default false
         * @dynamic false

         * @preserveWhiteSpace
         */
        public boolean getBase64DecodingRequired ();


        /**
         * No description provided.

         * @default false
         * @dynamic false

         * @param newValue - new value for attribute Base64DecodingRequired
         * @exception InvalidAttributeValueException
         * @preserveWhiteSpace
         */
        public void setBase64DecodingRequired (boolean newValue)
                throws InvalidAttributeValueException;



        
        /**
         * @default "JWTtokenIdentityAsserter"
         * @dynamic false
         * @owner RealmAdministrator
         * @VisibleToPartitions ALWAYS
         */
         public java.lang.String getName();

          

}
