export {
    redef enum Notice::Type += {
        Acces_Non_Autorise
    };
}

function get_zone_name(a: count): string {
    if ( a == 1025 ) return "WC";
    if ( a == 1027 ) return "Salle de conférence";
    if ( a == 1029 ) return "Accueil";
    return fmt("Registre inconnu (%d)", a);
}

event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, address: count, value: count) {
    local zone = get_zone_name(address);
    NOTICE([$note=Acces_Non_Autorise,
            $msg=fmt("ALERTE INTRUSION : Tentative de modification température dans [%s] ! Valeur injectée: %d, Attaquant: %s", zone, value, c$id$orig_h),
            $conn=c]);
}

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders, address: count, value: bool) {
    local z = (address == 0) ? "Ventilation Principale" : fmt("Sortie %d", address);
    NOTICE([$note=Acces_Non_Autorise,
            $msg=fmt("ALERTE INTRUSION : Modification d'état sur [%s] ! Etat: %b, Attaquant: %s", z, value, c$id$orig_h),
            $conn=c]);
}