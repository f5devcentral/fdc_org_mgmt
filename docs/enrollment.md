# Enrollment Instructions

This web application will help you enroll into the desired GitHub organization.  

## Authentication
The application will require authentication against your Azure Active Directory instance and GitHub.  For each identity provider, you will see an OAuth Scope request which will need to be accepted/authorized. 
![Azure OAuth Scope Request](images/azure_oauth.jpg)
![GitHub OAuth Scope Request](images/gh_oauth.jpg)

## Enroll
Once you are authenticated against Azure AD and GitHub you will see an enroll button:

![Enroll](images/enroll.png)

Click this button to enroll your GitHub user into the desired organization.

### Enrollment Response

If you are already a member of the GitHub organization you'll receive a warning stating such:
![Enrollment Warning](images/already_enrolled.png)

If you are not a member of the GitHub organziation, you'll receive a success notice telling you to check the email address associated with your GitHub account for an invite to the requested organization. 
![Enrolled](images/enrolled.png)

### Finish Enrollment
To finish enrollment, you will need to complete the instruction GitHub emailed to your associated email address.

![Finish Enrollment](images/finish_enrollment.png)