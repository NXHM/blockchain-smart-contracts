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
        state: bool,
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
    //Roles
    // 1 pa medico, 0 pa paciente
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
            role: u8,
        ) -> Result<(), String> {
            // Control Secundario de Datos
            if user_info.name.is_empty() || user_info.name.len() > 12 {
                return Err("Nombre no válido".to_string());
            }
            if user_info.lastname.is_empty() || user_info.lastname.len() > 12 {
                return Err("Apellido no válido".to_string());
            }
            if user_info.dni.is_empty() || user_info.dni.len() != 8 {
                return Err("DNI no válido".to_string());
            }
            if user_info.email.is_empty() || !user_info.email.contains('@') {
                return Err("Email no válido".to_string());
            }
            

            // Verificar si el dni ya tiene dos account_id asociados
            let accounts = self.accounts.get(&user_info.dni).unwrap_or([None, None]);
            let account_count = accounts.iter().filter(|acc| acc.is_some()).count();
            if account_count >= 2 {
                return Err("El DNI ya tiene dos cuentas asociadas".to_string());
            }

            // Verificar que los roles sean distintos
            for acc in accounts.iter().filter_map(|acc| acc.as_ref()) {
                let existing_role = self.roles.get(acc).unwrap_or(2); // 2 indica rol no definido
                if existing_role == role {
                    return Err("Ambos account_id no pueden tener el mismo rol".to_string());
                }
            }

            // Agregar el account_id al vector asociado con el dni
            let mut new_accounts = accounts;
            if new_accounts[0].is_none() {
                new_accounts[0] = Some(account_id);
            } else {
                new_accounts[1] = Some(account_id);
            }
            self.accounts.insert(&user_info.dni, &new_accounts);

            // Agregar el usuario al mapa de usuarios
            self.users.insert(&account_id, &user_info);

            // Agregar el rol al mapa de roles
            self.roles.insert(&account_id, &role);
            self.env().emit_event(RoleAssigned { account: account_id, role:role });
            // Emitir evento de usuario agregado
            self.env().emit_event(UserAdded { account: account_id });

            Ok(())
        }
    

        #[ink(message)]
        pub fn assign_role(
            &mut self,
            account_id: AccountId,
            role: u8
        ) -> String {
            self.roles.insert(account_id, &role);
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
            // Verificar si el permiso ya ha sido concedido
            if self.permissions.get((granter, grantee)).unwrap_or(false) {
                return Err("Permiso ya concedido".to_string());
            }

            // Insertar el permiso como true
            self.permissions.insert((granter, grantee), &true);

            // Actualizar la lista de grantees del granter
            let mut grantees_list = self.grantees.get(granter).unwrap_or_default();

            // Agregar al grantee si no está ya en la lista
            if !grantees_list.contains(&grantee) {
                grantees_list.push(grantee);
                self.grantees.insert(granter, &grantees_list);
            }

            // Emitir evento de permiso concedido
            self.env().emit_event(PermissionGranted { granter, grantee, state: true });

            Ok(())
        }


        #[ink(message)]
        pub fn revoke_permission(
            &mut self,
            granter: AccountId,
            grantee: AccountId,
        ) -> Result<(), String> {
            // Verificar si el permiso existe
            if !self.permissions.get((granter, grantee)).unwrap_or(false) {
                return Err("No existe permiso para revocar".to_string());
            }

            // Eliminar el permiso del mapping
            self.permissions.insert((granter, grantee), &false);

            // Actualizar la lista de grantees del granter
            let mut grantees_list = self.grantees.get(granter).unwrap_or_default();

            // Remover al grantee de la lista si está presente
            if let Some(pos) = grantees_list.iter().position(|&id| id == grantee) {
                grantees_list.remove(pos);
                self.grantees.insert(granter, &grantees_list);
            }

            // Emitir un evento para registrar que se ha revocado el permiso
            self.env().emit_event(PermissionGranted { granter, grantee, state: false });

            Ok(())
        }

        // === NUEVAS FUNCIONES DE CONSULTA ===

        /// Obtiene la información de un usuario por su AccountId.
        #[ink(message)]
        pub fn get_accounts(&self, dni: String) -> Vec<AccountId> {
            // Recuperar las cuentas asociadas al dni
            let accounts = self.accounts.get(&dni).unwrap_or([None, None]);

            // Filtrar las cuentas que no son None y devolverlas como un vector
            accounts.iter().filter_map(|&acc| acc).collect()
        }

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
