#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod access_control {
    use scale_info::prelude::format;
    use scale_info::prelude::string::String;
    use scale_info::prelude::vec::Vec;
    use ink_storage::Mapping; 
    use scale_info::prelude::string::ToString;
    #[ink::event]
    pub struct Log {
        #[ink(topic)]
        message: String,
    }

    #[ink::event]
    pub struct UserAdded {
        #[ink(topic)]
        account: AccountId,
    }

    #[ink::event]
    pub struct RoleAssigned {
        #[ink(topic)]
        account: AccountId,
        role: u8,
    }

    #[ink::event]
    pub struct PermissionGranted {
        #[ink(topic)]
        granter: AccountId,
        grantee: AccountId,
    }

    #[ink::event]
    pub struct AccessRequested {
        #[ink(topic)]
        requester: AccountId,
        target: AccountId,
    }

    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    #[cfg_attr(
        feature = "std",
        derive(ink::storage::traits::StorageLayout,Clone)
    )]
    pub struct UserInfo {
        name: String,
        lastname: String,
        dni: String,
        email: String,
    }

    #[ink(storage)]
    pub struct AccessControl {
        accounts: Mapping<String, [Option<AccountId>; 2]>,
        users: Mapping<AccountId, UserInfo>,
        roles: Mapping<AccountId, u8>,
        permissions: Mapping<(AccountId, AccountId), bool>,
        grantees: Mapping<AccountId, Vec<AccountId>>,
        access_requests: Mapping<AccountId, Vec<AccountId>>,
    }

    impl AccessControl {
        #[ink(constructor)]
        pub fn default() -> Self {
            Self {
                users: Mapping::default(),
                roles: Mapping::default(),
                accounts: Mapping::default(),
                permissions: Mapping::default(),
                grantees: Mapping::default(),
                access_requests: Mapping::default(),
            }
        }

        #[ink(message)]
        pub fn add_user(
            &mut self,
            account_id: AccountId,
            user_info: UserInfo,
        ) -> Result<(), String> {
            if user_info.name.is_empty() || user_info.name.len() > 12 {
                return Err("Nombre no válido".to_string());
            }
            
            self.users.insert(account_id, &user_info);
            self.env().emit_event(UserAdded { account: account_id });
            Ok(())
        }

        #[ink(message)]
        pub fn assign_role(
            &mut self,
            account_id: AccountId,
            role: u8,
            user_info: UserInfo,
        ) -> String {
            self.roles.insert(account_id, &role);
            self.users.insert(account_id, &user_info);
            self.env().emit_event(RoleAssigned { account: account_id, role });
            format!("Rol {} asignado a la cuenta {:?}", role, account_id)
        }

        #[ink(message)]
        pub fn request_access(&mut self, requester: AccountId, target: AccountId) {
            let mut requests = self.access_requests.get(requester).unwrap_or_default();
            requests.push(target);
            self.access_requests.insert(requester, &requests);
            self.env().emit_event(AccessRequested { requester, target });
        }

        #[ink(message)]
        pub fn grant_permission(
            &mut self,
            granter: AccountId,
            grantee: AccountId,
        ) -> Result<(), String> {
            if self.permissions.get((granter, grantee)).unwrap_or(false) {
                return Err("Permiso ya concedido".to_string());
            }
            self.permissions.insert((granter, grantee), &true);
            let mut grantees = self.grantees.get(granter).unwrap_or_default();
            grantees.push(grantee);
            self.grantees.insert(granter, &grantees);
            self.env().emit_event(PermissionGranted { granter, grantee });
            Ok(())
        }

        // === NUEVAS FUNCIONES DE CONSULTA ===

        /// Obtiene la información de un usuario por su AccountId.
        #[ink(message)]
        pub fn get_user_info(&self, account_id: AccountId) -> Option<UserInfo> {
            self.users.get(account_id)
        }

        /// Obtiene todas las solicitudes de acceso realizadas por un usuario.
        #[ink(message)]
        pub fn get_access_requests(&self, requester: AccountId) -> Vec<AccountId> {
            self.access_requests.get(requester).unwrap_or_default()
        }

        /// Obtiene todos los permisos concedidos por un usuario.
        #[ink(message)]
        pub fn get_granted_permissions(&self, granter: AccountId) -> Vec<AccountId> {
            self.grantees.get(granter).unwrap_or_default()
        }

        /// Verifica si un permiso existe entre dos usuarios.
        #[ink(message)]
        pub fn has_permission(&self, granter: AccountId, grantee: AccountId) -> bool {
            self.permissions.get((granter, grantee)).unwrap_or(false)
        }

        /// Obtiene el rol asignado a un usuario.
        #[ink(message)]
        pub fn get_role(&self, account_id: AccountId) -> Option<u8> {
            self.roles.get(account_id)
        }

        /// Verifica si un usuario existe.
        #[ink(message)]
        pub fn user_exists(&self, account_id: AccountId) -> bool {
            self.users.contains(account_id)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn test_add_user() {
            let mut access = AccessControl::default();
            let account_id = AccountId::from([0x1; 32]);
            let user_info = UserInfo {
                name: "Alice".to_string(),
                lastname: "Doe".to_string(),
                dni: "12345678".to_string(),
                email: "alice@example.com".to_string(),
            };
            access.add_user(account_id, user_info).unwrap();
            assert!(access.user_exists(account_id));
        }

        #[ink::test]
        fn test_get_user_info() {
            let mut access = AccessControl::default();
            let account_id = AccountId::from([0x1; 32]);
            let user_info = UserInfo {
                name: "Bob".to_string(),
                lastname: "Smith".to_string(),
                dni: "87654321".to_string(),
                email: "bob@example.com".to_string(),
            };
            access.add_user(account_id, user_info.clone()).unwrap();
            assert_eq!(access.get_user_info(account_id), Some(user_info));
        }

        #[ink::test]
        fn test_has_permission() {
            let mut access = AccessControl::default();
            let granter = AccountId::from([0x1; 32]);
            let grantee = AccountId::from([0x2; 32]);

            access.grant_permission(granter, grantee).unwrap();
            assert!(access.has_permission(granter, grantee));
        }
    }
}
