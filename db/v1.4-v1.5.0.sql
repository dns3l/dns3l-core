
/* Always do a backup / snapshot first.
Be sure to replace the table/proc prefix
"dns3l_" with yours if you altered the default.*/

delimiter //

ALTER TABLE dns3l_keycerts
  MODIFY COLUMN next_renewal_time TIMESTAMP NULL DEFAULT NULL,
  MODIFY COLUMN valid_start_time TIMESTAMP NULL DEFAULT NULL,
  MODIFY COLUMN valid_end_time TIMESTAMP NULL DEFAULT NULL//

ALTER TABLE dns3l_keycerts 
	ADD COLUMN last_access_time TIMESTAMP NULL DEFAULT NULL AFTER valid_end_time,
	ADD COLUMN access_count INTEGER DEFAULT 0 AFTER last_access_time//

CREATE PROCEDURE dns3l_read_increment (IN my_key_name CHAR(255), IN my_ca_id CHAR(63))
	BEGIN
	  UPDATE dns3l_keycerts SET last_access_time = utc_timestamp(), access_count = access_count + 1
	  WHERE key_name = my_key_name AND ca_id = my_ca_id;
	END//

CREATE TABLE IF NOT EXISTS dns3l_renew_info (
	renew_info TEXT
)//

CREATE PROCEDURE dns3l_set_renew_info (IN myrenew_info TEXT)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION, NOT FOUND
    BEGIN
    ROLLBACK;
    END;
    START TRANSACTION;
    TRUNCATE TABLE dns3l_renew_info;
    INSERT INTO dns3l_renew_info VALUES (myrenew_info);
    COMMIT;
END//

delimiter ;
