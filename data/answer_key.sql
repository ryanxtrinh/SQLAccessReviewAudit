-- Answer key: every control failure planted by DataGenerator.java.
-- Verify.java loads this and compares it with what each audit query finds.
DROP TABLE IF EXISTS planted_issues;
CREATE TABLE planted_issues (
    check_id    TEXT    NOT NULL,   -- which audit test should find it
    account_id  INTEGER,            -- for account-level tests
    employee_id INTEGER             -- for person-level tests (SoD)
);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-01', 1421);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-01', 1422);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-01', 1014);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-01', 1015);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-01', 1169);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-01', 1170);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-02', 1421);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-02', 1014);
INSERT INTO planted_issues (check_id, employee_id) VALUES ('AR-03', 50);
INSERT INTO planted_issues (check_id, employee_id) VALUES ('AR-03', 30);
INSERT INTO planted_issues (check_id, employee_id) VALUES ('AR-03', 65);
INSERT INTO planted_issues (check_id, employee_id) VALUES ('AR-03', 19);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-04', 1377);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-04', 1404);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-04', 1044);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-04', 1232);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-04', 1098);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-04', 1469);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-04', 1470);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-05', 1108);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-05', 1308);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-05', 1444);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-06', 1471);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-06', 1472);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-06', 1473);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-07', 1474);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-07', 1475);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-08', 1002);
INSERT INTO planted_issues (check_id, account_id) VALUES ('AR-08', 1308);
