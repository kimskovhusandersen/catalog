# Project: Item Catalog

The Item Catalog project is the second project in Udacity's full stack web development nanodegree program. The task was to build an application that provides a list of items within a variety of categories, as well as provide a user registration and authentication system. Next we added a search functionality that allows users to look for search for items or categories within the Item Catalog. We also connected the search to Wikipedia with the help from the MediaWiki API and added a feature that allows logged-in users to add wikipedia content as a category or item in the Item Catalog.


## The webapp makes use of

- [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/) to manage our VM.
- [Python](https://docs.python.org/3/)
- [Flask](https://palletsprojects.com/p/flask/)
- [SQLite](https://www.sqlite.org/index.html)
- [oauth2client.client module](https://oauth2client.readthedocs.io/en/latest/source/oauth2client.client.html) to handle authentication and authorization via Google and Facebook
- [Flask-limiter](https://flask-limiter.readthedocs.io/en/stable/) to handle limitation of API requests
- [marshmallow-sqlalchemy](https://marshmallow-sqlalchemy.readthedocs.io/en/latest/) to handle (de)serialization

## Getting started

- To get started, install vagrant and VirtualBox. You'll find a detailed guide for installing [here](https://classroom.udacity.com/nanodegrees/nd004-ent/parts/72d6fe39-3e47-45b4-ac52-9300b146094f/modules/0f94ae26-c39d-4231-924b-b1eb6e06cf41/lessons/5475ecd6-cfdb-4418-85a2-f2583074c08d/concepts/14c72fe3-e3fe-4959-9c4b-467cf5b7c3a0).
- Cd into the _vagrant_ directory and create a folder called _catalog_
- Download all the files from the [catalog repository](https://github.com/kimskovhusandersen/catalog) and put them into the _catalog_ directory.
- To enable login with Google via the Item Catalog app, please visit [console.developers.google.com](https://console.developers.google.com) and create a new project. Download the client secret file (JSON) from that project, rename it to `client_secrets.json` and store it in the _catalog_ directory. See detailed instructions via Udacity's instructional video: [Step 1 Create Client ID & Secret](https://classroom.udacity.com/courses/ud330/lessons/3967218625/concepts/39636486130923)
- To enable login with Facebook via The Item Catalog app, please register a new app with Facebook. Store the _app_id_ and _app_secret_ in a new file that you call `fb_client_secrets.json`, and save the file in the _catalog_ directory. See detailed instructions via Udacity's instructional video: [Registering your App with Facebook](https://classroom.udacity.com/courses/ud330/lessons/3951228603/concepts/39497787740923)
- Go to _templates_ in the _catalog_ directory and open _login.html_ in a text editor. Replace the value of the `client_id` with the client_id of your newly created project and replace the value of the `appId` with your newly create Facebook appId.
- Start up the VM and login by using the commands `vagrant up` followed by `vagrant ssh`.
- On your virtual Linux machine, cd into _/vagrant/catalog_ and use the command `python views.py` to run the webapp.
- Open your favorite browser and go to [localhost:8000](http://localhost:8000/)
- Use the catalog to browse categories and items and login with Facebook or Google free of charge to create, edit or delete categories and items.
- To make use of the Catalog API, create a free user via `POST http://localhost:8000/api/users`
- See API documentation at [http://localhost:8000/API/](http://localhost:8000/API/)
- To close the connection from the command line press `ctrl + c`, logout of the VM with the command `ctrl + d` and shutdown your VM with the command `vagrant halt`.

## Author

- **[Kim Skovhus Andersen](https://github.com/kimskovhusandersen)**

## Acknowledgement

- Udacity provided the training, review and feedback
