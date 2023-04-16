"""
PyGitHub wrapper
"""
from github import Github, AppAuthentication, UnknownObjectException, NamedUser

def unknown_exception(func):
    """
    Decorator to catch UnknownObjectException

    Args:
        func (function): function to decorate
    
    Returns:
        function: decorated function
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except UnknownObjectException:
            return None
    return wrapper

class User():
    """
    User class to map GitHub NamedUser to a simpler object

    Args:
        github_user (NamedUser): GitHub NamedUser object
    
    Returns:
        User: User object
    """
    def __init__(self, github_user: NamedUser):
        self.name = github_user.name
        self.email = github_user.email
        self.login = github_user.login
        # pylint: disable=C0103
        self.id = github_user.id
        # pylint: enable=C0103
        self.avatar_url = github_user.avatar_url

class UserIsAlreadyAMember(Exception):
    """
    Exception to raise when a user is already a member of an organization
    """
    def __init__(self):
        super().__init__("User is already a member of the organization")

def user(func):
    """
    Decorator to map GitHub NamedUser to a simpler object
    
    Args:
        func (function): function to decorate
        
    Returns:
        function: decorated function
    """
    def wrapper(*args, **kwargs):
        github_user = func(*args, **kwargs)
        if github_user is not None:
            mapped_user = User(github_user)
            return mapped_user
        else:
            return None
    return wrapper

class GitHubOrg:
    """
    GitHubOrg class to wrap PyGitHub

    Args:
        org_name (str): GitHub organization name
        app_id (str): GitHub App ID
        private_key (str): GitHub App private key
        installation_id (str): GitHub App installation ID
        
    Returns:
        GitHubOrg: GitHubOrg object
    """
    def __init__(self, org_name, app_id, private_key, installation_id):
        self.org_name = org_name
        self.app_auth = AppAuthentication(
            int(app_id),
            private_key,
            int(installation_id))
        # pylint: disable=C0103
        self.g = Github(app_auth=self.app_auth)
        self.o = self.g.get_organization(self.org_name)
        # pylint: enable=C0103

    @unknown_exception
    def add_org_member(self, username):
        """
        Add a user to the organization
        
        Args:
            username (str): GitHub username
            
        Returns:
            bool: True if successful, False if not
        """
        named_user = self.g.get_user(username)
        if self.o.has_in_members(named_user):
            raise UserIsAlreadyAMember
        self.o.add_to_members(named_user)

        # TODO: validate that addition to org happens immediately
        if self.o.has_in_members(named_user):
            return True
        else:
            return False

    @unknown_exception
    def delete_org_member(self, username):
        """
        Delete a user from the organization
        
        Args:
            username (str): GitHub username
            
        Returns:
            bool: True if successful, False if not
        """
        named_user = self.g.get_user(username)
        self.o.remove_from_members(named_user)
        # TODO: validate removal from org happens immediately
        if self.o.has_in_members(named_user):
            return False
        else:
            return True

    def get_org(self):
        """
        Get the organization object
        """
        return self.o

    def get_org_members(self):
        """
        Get the organization members
        """
        return self.o.get_members()

    def get_org_invitations(self):
        """
        Get the organization invitations
        """
        return self.o.invitations()

    @user
    @unknown_exception
    def get_user(self, username):
        """
        Get a user object
        
        Args:
            username (str): GitHub username
            
        Returns:
            User: User object"""
        return self.g.get_user(username)

    @unknown_exception
    def is_member(self, username):
        """
        Check if a user is a member of the organization
        
        Args:
            username (str): GitHub username
            
        Returns:
            bool: True if user is a member, False if not
        """
        named_user = self.g.get_user(username)
        return self.o.has_in_members(named_user)
    