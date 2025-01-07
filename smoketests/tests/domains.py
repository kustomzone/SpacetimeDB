from .. import Smoketest, random_string

class Domains(Smoketest):
    AUTOPUBLISH = False

    def test_set_name(self):
        """Tests the functionality of the set-name command"""

        self.publish_module()

        rand_name = random_string()

        # This should throw an exception before there's a db with this name
        with self.assertRaises(Exception):
            self.spacetime("logs", rand_name)

        self.spacetime("rename", "--to", rand_name, self.database_identity)

        # Now we're essentially just testing that it *doesn't* throw an exception
        self.spacetime("logs", rand_name)

    def test_set_to_existing_name(self):
        """Test that we can't rename to a name already in use"""

        self.publish_module()
        id_to_rename = self.database_identity

        rename_to = random_string()
        self.publish_module(rename_to)

        # This should throw an exception because there's a db with this name
        with self.assertRaises(Exception):
            self.spacetime("rename", "--to", rename_to, id_to_rename)
