import base64
import datetime
import json
import time
from abc import ABCMeta
from abc import abstractmethod
from logging import getLogger

import pytz
import requests
from .conf import settings
from .utils import timezone
from requests_oauthlib import OAuth1
from rest_framework.exceptions import AuthenticationFailed, APIException, PermissionDenied

from .models import Competition
from .models import StepCountDataLog, StepCountData
from .models import User, StepTrackingDevice
from .models import FitbitUser, GoogleFitUser, GarminUser
from .models import Competitor

QUALIFYING_DAILY_STEP_COUNT = 4000
SYNC_DAYS_RANGE = 14


class DeviceConnection(metaclass=ABCMeta):
    def __init__(self, User, device_type, logger=None):
        self.User = User
        self.device_type = device_type
        if logger:
            self.logger = logger
        else:
            self.logger = getLogger('logger_device_connections')

    def get_device_type(self):
        return self.device_type

    @abstractmethod
    def connect_device(self, authorization_data):
        self.logger.info('Connecting {} device for User {}', self.device_type, self.User)

    def disconnect_device(self):
        auth_excluded_devices = ['apple', 'samsung']
        connection = get_connection(self.User)
        if connection.get_device_type() not in auth_excluded_devices:
            connection.delete_user()
        third_party_connection = StepTrackingDevice.objects.filter(
            User=self.User,
            connection_status=True
        )
        for device_connection in third_party_connection:
            self.logger.info(
                'Disconnecting {} device for User {} - {}',
                device_connection.connection_name,
                self.User,
                self.User.email
            )
            device_connection.disconnect_device()

    @abstractmethod
    def get_step_data(self, start_date=None, end_date=None):
        self.logger.info('====================================================================')
        self.logger.info('Starting sync for user: {}'.format(self.User))
        self.logger.info('Device type: {}'.format(self.device_type))


    def get_existing_step_data(self, Competitor_id, start_date=None, end_date=None):
        Competitor = Competitor.objects.get(id=Competitor_id)
        if not start_date:
            start_date = Competitor.team.Competition.start_date
        if not end_date:
            end_date = Competitor.team.Competition.end_date

        measurements = StepCountData.objects.filter(
            User=self.User,
            source=self.device_type,
            date_of_measurement__gte=start_date,
            date_of_measurement__lte=end_date
        )

        step_sum = calculate_step_count(measurements)

        return step_sum

    def get_existing_step_data_since_today(self, days=44):
        steps = StepCountData.objects.get_max_step_data_since_today(self.User, days)
        return steps

    def get_existing_step_data_as_list(self):
        steps = self.get_existing_step_data_since_today()
        steps_list = []
        for day in steps:
            steps_list.append({
                'date': day.date_of_measurement.strftime('%b %d, %Y'),
                'step_count': int(day.value)
            })
        return steps_list

    def save_step_data_as_list(self, response_data):
        for step_data in response_data:
            StepCountDataLog.objects.create(
                User=self.User,
                source=self.device_type,
                resource='steps',
                date_of_measurement=step_data['date'],
                value=int(float(step_data['step_count']))
            )

    def get_existing_step_history_since_today(self, days):
        today = datetime.date.today()
        days_period = today - datetime.timedelta(days=days)
        steps = StepCountData.objects.filter(
            User=self.User,
            source=self.device_type,
            date_of_measurement__gte=days_period,
            date_of_measurement__lte=today
        ).order_by('-value')

        return steps

    def get_existing_step_history_as_list(self, days):
        steps = StepCountData.objects.get_max_step_data_since_today_dict(
            self.User, days
        ).order_by('-date_of_measurement')
        steps_list = []
        for day in steps:
            steps_list.append({
                'date': day['date_of_measurement'].strftime('%b %d, %Y'),
                'step_count': int(day['max_steps'])
            })
        return steps_list

    @staticmethod
    def get_initial_daily_step_goal(Competition_id):
        Competition = Competition.objects.get(id=Competition_id)
        if Competition.Competition_type.slug == "million-step-Competition":
            steps = Competition.team_average_step_goal
        else:
            steps = 10000

        return steps

    def get_adjusted_step_goal(self, Competition_id):
        median = int(self.get_median().replace(',', ''))
        Competition = Competition.objects.get(id=Competition_id)
        return round(median + (median * Competition.goal_setting_percentage / 100))

    @staticmethod
    def get_daily_step_goal(Competitor_id):
        return Competitor.objects.get(id=Competitor_id).individual_goal

    def get_median(self):
        steps = self.get_existing_step_data_since_today()
        qs = steps.filter(value__gte=QUALIFYING_DAILY_STEP_COUNT).order_by('value')
        qualifying_days_count = qs.count()
        qualifying_days = list(qs.all())
        median = '0'
        if qualifying_days_count > 0:
            if qualifying_days_count % 2 == 0:
                middle_value = qualifying_days[int(qualifying_days_count / 2) - 1]
                next_middle_value = qualifying_days[int(qualifying_days_count / 2)]
                median = (middle_value.value + next_middle_value.value) / 2
                median = format(int(round(median)), ',')
            else:
                median = qualifying_days[int((qualifying_days_count - 1) / 2)]
                median = format(int(round(median.value)), ',')
        return median

    def get_qualifying_days(self):
        steps = self.get_existing_step_data_since_today()
        qualifying_days = steps.filter(value__gte=QUALIFYING_DAILY_STEP_COUNT)
        qualifying_days_list = []
        for day in qualifying_days:
            qualifying_days_list.append({
                'date_of_measurement': day.date_of_measurement.strftime('%b %d, %Y'),
                'value': format(int(day.value), ',')
            })
        return qualifying_days_list

    def get_non_qualifying_days(self):
        steps = self.get_existing_step_data_since_today()
        non_qualifying_days = steps.filter(value__lt=QUALIFYING_DAILY_STEP_COUNT)
        non_qualifying_days_list = []
        for day in non_qualifying_days:
            non_qualifying_days_list.append({
                'date_of_measurement': day.date_of_measurement.strftime('%b %d, %Y'),
                'value': format(int(day.value), ',')
            })
        return non_qualifying_days_list

    def get_qualifying_and_non_qualifying_days(self):
        steps = self.get_existing_step_data_since_today()

        qualifying_days = steps.filter(value__gte=QUALIFYING_DAILY_STEP_COUNT)
        qualifying_days_list = []
        for day in qualifying_days:
            qualifying_days_list.append({
                'date_of_measurement': day.date_of_measurement.strftime('%b %d, %Y'),
                'value': format(int(day.value), ',')
            })

        non_qualifying_days = steps.filter(value__lt=QUALIFYING_DAILY_STEP_COUNT)
        non_qualifying_days_list = []
        for day in non_qualifying_days:
            non_qualifying_days_list.append({
                'date_of_measurement': day.date_of_measurement.strftime('%b %d, %Y'),
                'value': format(int(day.value), ',')
            })

        return {
            'qualifying_days': qualifying_days_list,
            'non_qualifying_days': non_qualifying_days_list
        }

    def get_step_average(self, days=7):
        avg_step_value = 0
        today = datetime.date.today()
        one_day_before = today - datetime.timedelta(1)
        days_period = today - datetime.timedelta(days)
        measurements = StepCountData.objects.filter(
            User=self.User,
            date_of_measurement__gte=days_period,
            date_of_measurement__lte=one_day_before,
            source=self.device_type
        )
        step_sum = calculate_step_count(measurements)

        if step_sum:
            avg_step_value = step_sum / days
        return avg_step_value

    @staticmethod
    def get_adjusted_step_average(Competitor_id):
        Competitor = Competitor.objects.get(id=Competitor_id)
        if Competitor.team.Competition.Competition_type.slug == "million-step-Competition":
            steps = Competitor.team.Competition.team_average_step_goal
        else:
            steps = Competitor.individual_goal * Competitor.team.Competition.Competition_duration()
        steps_needed = steps - Competitor.total_steps()
        remaining_days = Competitor.team.Competition.Competition_remaining_days()
        steps_needed = steps_needed / float(remaining_days if remaining_days else 1)
        if steps_needed <= 0:
            return 0
        return steps_needed

    def get_last_sync_time(self, Competitor_id):
        Competitor = Competitor.objects.get(id=Competitor_id)

        steps_to_date = StepCountDataLog.objects.filter(
            User=self.User,
            date_of_measurement__gte=Competitor.team.Competition.start_date,
            date_of_measurement__lte=Competitor.team.Competition.end_date
        ).latest('created')

        unaware_posted_on = steps_to_date.modified
        posted_on = unaware_posted_on.replace(tzinfo=pytz.UTC)
        now = datetime.datetime.now(pytz.UTC)

        difference = now - posted_on
        minutes = difference.seconds // 60

        if hasattr(difference, 'days') and difference.days > 365:
            year = difference.days // 365
            return '1 year ago.' if year == 1 else format('{} years ago.', str(year))
        if hasattr(difference, 'days') and difference.days > 30:
            month = difference.days // 30
            return '1 month ago.' if month == 1 else format('{} months ago.', str(month))
        elif hasattr(difference, 'days') and difference.days > 0:
            return '1 day ago.' if difference.days == 1 else format('{} days ago.', str(difference.days))
        elif minutes and minutes > 60:
            return format('{} hours ago.', str(minutes // 60))
        elif minutes and minutes > 10:
            return 'Less than an hour ago.'
        elif minutes and minutes > 1:
            return 'Less than an hour ago.'
        else:
            return 'Moments ago.'

    @staticmethod
    def _is_token_expired(expiration_date):
        now_minus_ten_seconds = time.mktime(timezone.now().timetuple())
        return expiration_date < now_minus_ten_seconds

    @staticmethod
    def _convert_seconds_to_datetime(seconds):
        created_on = timezone.datetime.now()
        expires_on = created_on + timezone.timedelta(seconds=seconds)
        return expires_on


class FitbitConnection(DeviceConnection):
    def connect_device(self, code):
        if 'access_token' not in code:
            fitbit_user_data = self.get_access_token(code)
            user_response = self.save_user(fitbit_user_data)
        else:
            user_response = self.save_user(code)
        if user_response is not True:
            get_connection(self.User).disconnect_device()
            raise AuthenticationFailed(user_response)
        start_date = timezone.now().date()
        end_date = timezone.datetime.now().date() - timezone.timedelta(days=44)
        get_connection(self.User).get_step_data(start_date, end_date)

    def get_access_token(self, code):
        consumer_key = settings.THIRDPARTY_CREDENTIALS['FITBIT']['CONSUMER_KEY']
        consumer_secret = settings.THIRDPARTY_CREDENTIALS['FITBIT']['CONSUMER_SECRET']
        redirect_uri = settings.THIRDPARTY_CREDENTIALS['FITBIT']['REDIRECT_URI']
        parameters = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': consumer_key,
            'redirect_uri': redirect_uri
        }

        authorization_key = consumer_key + ':' + consumer_secret
        b64secret = base64.b64encode(authorization_key.encode())
        fitbit_access_token_request_header = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic {}'.format(b64secret.decode())
        }

        response = requests.post(
            settings.FITAPP_TOKEN_URL,
            params=parameters,
            headers=fitbit_access_token_request_header,
            stream=True
        )
        response_status_code = response.status_code
        response = response.json()

        if response_status_code != 200:
            response = self.get_access_token_mobile(code)
            response_status_code = response.status_code
            response = response.json()
            if response_status_code != 200:
                get_connection(self.User).disconnect_device()
                self.logger.info("ACCESS TOKEN NOT CREATED: {}".format(response['errors'][0]['message']))
                raise AuthenticationFailed(response['errors'][0]['message'])
        return response

    def get_access_token_mobile(self, code):
        mobile_consumer_key = settings.THIRDPARTY_CREDENTIALS['FITBIT-MOB']['CONSUMER_KEY']
        mobile_consumer_secret = settings.THIRDPARTY_CREDENTIALS['FITBIT-MOB']['CONSUMER_SECRET']
        mobile_redirect_uri = settings.THIRDPARTY_CREDENTIALS['FITBIT-MOB']['REDIRECT_URI']
        parameters = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': mobile_consumer_key,
            'redirect_uri': mobile_redirect_uri
        }

        authorization_key = mobile_consumer_key + ':' + mobile_consumer_secret
        b64secret = base64.b64encode(authorization_key.encode())
        fitbit_access_token_request_header = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic {}'.format(b64secret.decode())
        }

        response = requests.post(
            settings.FITAPP_TOKEN_URL,
            params=parameters,
            headers=fitbit_access_token_request_header,
            stream=True
        )
        return response

    def retrieve_token_state(self, access_token):
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer {}'.format(access_token)
        }
        parameters = {
            'token': access_token
        }

        response = requests.post(
            'https://api.fitbit.com/1.1/oauth2/introspect',
            data=parameters,
            headers=headers,
            stream=True
        )
        response_status_code = response.status_code
        response = response.json()
        if response_status_code == 200:
            if response['active'] == 0:
                return 'Access token invalid'
            if response['active'] == 1 and 'ACTIVITY' not in response['scope']:
                return 'This application does not have permission to access activity'
        else:
            return 'Access token invalid'
        return True

    def save_user(self, form_data):
        force_connect = form_data.get('force_connect', None)
        fitbit_user = FitbitUser.objects.filter(fitbit_user=form_data['user_id']).exclude(user=self.User)
        if force_connect is True:
            # When user chooses to connect device anyway
            StepTrackingDevice.objects.filter(User=fitbit_user.first().user).delete()
            fitbit_user.delete()

            FitbitUser.objects.create(
                fitbit_user=form_data['user_id'],
                user=self.User,
                access_token=form_data['access_token'],
                refresh_token=form_data['refresh_token'],
                expires_at=time.mktime(timezone.now().timetuple()) + form_data['expires_in']
            )

            return True
        elif force_connect is False:
            if fitbit_user.exists():
                response = f'We are having trouble connecting your device because it is already connected to' \
                    f' a HealthyWage account associated with {fitbit_user[0].user.email}.\n To connect your device to' \
                    f' this account and disconnect your device from {fitbit_user[0].user.email},' \
                    f' click "Connect Device".'
                return response
        else:
            # Left for compatibility with old versions of mobile apps
            if fitbit_user.exists():
                response = ('We are having trouble connecting your device because it is already connected '
                            'to a HealthyWage account associated with %s.\nTo connect your device to %s you'
                            ' must first logout and then login with %s and disconnect the device from that '
                            'account' % (fitbit_user[0].user.email, self.User,
                                         fitbit_user[0].user.email))
                return response

        FitbitUser.objects.update_or_create(
            fitbit_user=form_data['user_id'],
            defaults={
                'user': self.User,
                'access_token': form_data['access_token'],
                'refresh_token': form_data['refresh_token'],
                'expires_at': time.mktime(timezone.now().timetuple()) + form_data['expires_in']
            }
        )
        return True

    def delete_user(self):
        self.logger.info("FITBIT ACCOUNT DELETED FOR USER {}".format(self.User))
        FitbitUser.objects.filter(user=self.User).delete()

    def save_step_data(self, step_data):
        if 'activities-steps' in step_data:
            for activity_step in step_data['activities-steps']:
                StepCountDataLog.objects.create(
                    User=self.User,
                    source=self.device_type,
                    resource='steps',
                    date_of_measurement=activity_step['dateTime'],
                    value=int(float(activity_step['value']))
                )

    def refresh_access_token(self, fitbit_user):
        refresh_token = fitbit_user.refresh_token
        self.logger.info('User refresh token: {}'.format(fitbit_user.refresh_token))

        # Getting new access token and refresh token
        parameters = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }
        consumer_key = settings.THIRDPARTY_CREDENTIALS['FITBIT']['CONSUMER_KEY']
        consumer_secret = settings.THIRDPARTY_CREDENTIALS['FITBIT']['CONSUMER_SECRET']
        authorization_key = consumer_key + ':' + consumer_secret
        b64secret = base64.b64encode(authorization_key.encode())
        fitbit_refresh_token_request_header = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic {}'.format(b64secret.decode())
        }

        response = requests.post(
            settings.FITAPP_TOKEN_URL,
            params=parameters,
            headers=fitbit_refresh_token_request_header,
            stream=True
        )
        response_status_code = response.status_code
        # If couldn't refresh token
        if response_status_code != 200:
            if response_status_code == 502:
                raise ConnectionToFitbitFailed("Couldn't connect to Fitbit: Error 502 - Bad Gateway")
            response = response.json()

            if 'invalid_grant' in response['errors'][0]['errorType']:
                response = self.refresh_access_token_mobile(fitbit_user)
                try:
                    fitbit_user.refresh_token = response['refresh_token']
                    fitbit_user.access_token = response['access_token']
                    fitbit_user.expires_at = time.mktime(timezone.now().timetuple()) + response['expires_in']
                    fitbit_user.save()
                    return response
                except (IndexError, Exception):
                    raise PermissionDenied("User {} access token not refreshed".format(
                        self.User.email,
                    ))

            error_message = "User {} access token not refreshed: {}".format(
                self.User.email,
                response['errors'][0]['errorType']
            )
            self.logger.info(error_message)
            raise PermissionDenied(error_message)

        response = response.json()
        # Saving new refresh token, access token and expires at to FitbitUser model for later use
        fitbit_user.refresh_token = response['refresh_token']
        fitbit_user.access_token = response['access_token']
        fitbit_user.expires_at = time.mktime(timezone.now().timetuple()) + response['expires_in']
        fitbit_user.save()
        return response

    def refresh_access_token_mobile(self, fitbit_user):
        refresh_token = fitbit_user.refresh_token
        self.logger.info('User refresh token: {}'.format(fitbit_user.refresh_token))

        # Getting new access token and refresh token
        parameters = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
        }

        CONSUMER_KEY = '22D2H2'
        CONSUMER_SECRET = '9979f4e0177ea2afba5d87b564543730'

        authorization_key = CONSUMER_KEY + ':' + CONSUMER_SECRET
        b64secret = base64.b64encode(authorization_key.encode())
        fitbit_refresh_token_request_header = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic {}'.format(b64secret.decode())
        }

        response = requests.post(
            settings.FITAPP_TOKEN_URL,
            params=parameters,
            headers=fitbit_refresh_token_request_header,
            stream=True
        )
        response_status_code = response.status_code
        response = response.json()
        # If couldn't refresh token
        if response_status_code != 200:
            if 'invalid_grant' in response['errors'][0]['errorType']:
                StepTrackingDevice.objects.filter(User=self.User).latest('created').disconnect_device()
            error_message = "User {} access token not refreshed: {}".format(
                self.User.email,
                response['errors'][0]['errorType']
            )
            self.logger.info(error_message)
            raise PermissionDenied(error_message)

        # Saving new refresh token, access token and expires at to FitbitUser model for later use
        fitbit_user.refresh_token = response['refresh_token']
        fitbit_user.access_token = response['access_token']
        fitbit_user.expires_at = time.mktime(timezone.now().timetuple()) + response['expires_in']
        fitbit_user.save()
        return response

    def get_step_data(self, start_date=None, end_date=None):
        super(FitbitConnection, self).get_step_data(start_date, end_date)
        start_date = timezone.now().date() if not start_date else start_date
        end_date = timezone.datetime.now().date() - timezone.timedelta(hours=24) if not end_date else end_date

        # Getting fitbit user data
        fbuser = FitbitUser.objects.get(user=self.User)

        # If access token is expired - get fresh access token
        response = None
        if self._is_token_expired(fbuser.expires_at):
            response = self.refresh_access_token(fbuser)

        # Forming the data for a request
        if response:
            access_token = response['access_token']
        else:
            access_token = fbuser.access_token

        get_steps_url = 'https://api.fitbit.com/1/user/{0}/activities/steps/date/{1}/{2}.json'.format(
            fbuser.fitbit_user,
            end_date,
            start_date
        )
        headers = {
            'Authorization': 'Bearer {}'.format(access_token)
        }

        # Requesting step data
        response = requests.get(get_steps_url, headers=headers)
        status_code = response.status_code

        # Checking responses
        if status_code == 200:
            response = json.loads(response.content)
            # Saving step data to StepCountData
            self.save_step_data(response)
            return response
        if status_code >= 500:
            raise ConnectionToFitbitFailed("Couldn't connect to Fitbit")
        else:
            response = json.loads(response.content)
            error_message = 'User {}, error: {}'.format(
                self.User.email,
                response['errors'][0]['errorType']
            )
            self.logger.info(error_message)
            raise PermissionDenied(error_message)


class GarminConnection(DeviceConnection):
    def connect_device(self, authorization_data):
        # calls the method to get garmin user details.
        # input : oauth_token, oauth_token_secret, output : None
        self.save_user(authorization_data)
        start_date = timezone.datetime.now()
        end_date = timezone.datetime.now() - timezone.timedelta(days=44)
        get_connection(self.User).get_step_data(start_date.date(), end_date.date())

    def save_user(self, form_data):
        garmin_user, created = GarminUser.objects.get_or_create(
            user=self.User,
        )
        garmin_user.oauth_token = form_data['oauth_token']
        garmin_user.oauth_token_secret = form_data['oauth_secret']
        garmin_user.save()

    def save_step_data(self, step_data):
        if step_data:
            for activity in step_data:
                StepCountDataLog.objects.create(
                    User=self.User,
                    source=self.device_type,
                    resource='steps',
                    date_of_measurement=activity['calendarDate'],
                    value=int(float(activity['steps']))
                )

    def delete_user(self):
        self.logger.info("GARMIN ACCOUNT DELETED FOR USER {}".format(self.User))
        GarminUser.objects.filter(user=self.User).delete()

    def get_step_data(self, start_date=None, end_date=None):
        super(GarminConnection, self).get_step_data(start_date, end_date)

        start_date = timezone.datetime.now().date() if not start_date else start_date
        end_date = timezone.datetime.now().date() - timezone.timedelta(days=1) if not end_date else end_date

        days = (start_date - end_date).days

        measurement_data = StepCountData.objects.filter(User=self.User, source=self.device_type)
        last_sync_date = measurement_data.latest(
            'date_of_measurement').date_of_measurement if measurement_data.exists() else None

        if last_sync_date:
            days = (start_date - last_sync_date).days

        # Getting garmin user data
        garmin_user = GarminUser.objects.get(user=self.User)
        oauth_token = garmin_user.oauth_token
        oauth_token_secret = garmin_user.oauth_token_secret
        new_start_date = start_date + timezone.timedelta(days=1)
        for i in range(days):
            new_end_date = new_start_date - timezone.timedelta(days=1)
            end_date_seconds = int(time.mktime(new_end_date.timetuple()))
            start_date_seconds = int(time.mktime(new_start_date.timetuple()))

            # 4th of November 2018 time shift caused amount of seconds to be 90000, which was above max of 86400
            start_end_dates_difference = start_date_seconds - end_date_seconds
            if start_end_dates_difference != 86400:
                deviation = start_end_dates_difference - 86400
                start_date_seconds -= deviation

            get_steps_url = 'https://healthapi.garmin.com/wellness-api/rest/dailies?uploadStartTimeInSeconds={0}' \
                            '&uploadEndTimeInSeconds={1}'.format(
                                end_date_seconds,
                                start_date_seconds
                            )
            headeroauth = OAuth1(settings.THIRDPARTY_CREDENTIALS['GARMIN']['CONSUMER_KEY'],
                                 client_secret=settings.THIRDPARTY_CREDENTIALS['GARMIN']['CONSUMER_SECRET'],
                                 resource_owner_key=oauth_token, resource_owner_secret=oauth_token_secret,
                                 signature_type='auth_header')
            # Requesting step data
            response = requests.get(get_steps_url, auth=headeroauth, verify=False)
            status_code = response.status_code
            response = json.loads(response.content)
            # Checking responses
            if status_code == 200:
                self.save_step_data(response)
            else:
                if not response.get('errorMessage', None):
                    error_message = f"User {self.User.email}. Couldn't connect to Garmin!" \
                        f" HTTP status code: {status_code}"
                else:
                    error_message = f"User {self.User.email}, error: {response['errorMessage']}"
                self.logger.info(error_message)
                raise PermissionDenied(error_message)
            new_start_date = new_end_date

    def get_existing_step_data_as_list(self):
        steps = self.get_existing_step_data_since_today().order_by("date_of_measurement")
        steps_list = []
        for day in steps:
            steps_list.append({
                'date': day.date_of_measurement.strftime('%Y-%m-%d'),
                'step_count': int(day.value)
            })
        return steps_list


class SamsungConnection(DeviceConnection):
    def connect_device(self, authorization_data):
        pass

    def write_device_data_log(self, response_data):
        pass

    def get_step_data(self, start_date=None, end_date=None):
        pass

    def save_step_data(self, step_data):
        for activity_step in step_data:
            StepCountData.objects.update_or_create(
                User=self.User,
                source=self.device_type,
                resource='steps',
                date_of_measurement=activity_step['date_of_measurement'],
                defaults={'value': int(float(activity_step['value']))}
            )


class AppleConnection(DeviceConnection):
    def connect_device(self, authorization_data):
        pass

    def write_device_data_log(self, response_data):
        pass

    def get_step_data(self, start_date=None, end_date=None):
        pass

    def save_step_data(self, step_data):
        for activity_step in step_data:
            StepCountData.objects.update_or_create(
                User=self.User,
                source=self.device_type,
                resource='steps',
                date_of_measurement=activity_step['date_of_measurement'],
                defaults={'value': int(float(activity_step['value']))}
            )


class GoogleConnection(DeviceConnection):
    def connect_device(self, authorization_data):
        # Exchange authorization code for tokens and expiration time
        # tokens_and_expiration_time = self.get_auth_tokens(authorization_data)
        if 'access_token' in authorization_data:
            # Save obtained data to GoogleFitUser model
            self.save_user(authorization_data)

    def get_auth_tokens(self, authorization_data):
        parameters = {
            'code': authorization_data['code'],
            'access_type': 'offline',
            'grant_type': 'authorization_code',
            'prompt': 'consent',
            'client_id': settings.GOOGLE_FIT_CLIENT_ID,
            'scope': settings.GOOGLE_FIT_OAUTH_SCOPE,
            'response_type': 'code',
            'redirect_uri': settings.GOOGLE_FIT_REDIRECT_URI
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        response = requests.post(
            settings.GOOGLE_FIT_AUTH_URI,
            params=parameters,
            headers=headers,
            stream=True
        )
        response_status_code = response.status_code
        response = response.json()
        if response_status_code != 200:
            self.logger.info("GOOGLE FIT ACCESS TOKEN NOT CREATED FOR USER {}".format(self.User))

        return response['access_token'], response['refresh_token'], response['expires_in']

    def save_user(self, form_data):
        GoogleFitUser.objects.update_or_create(
            user=self.User,
            access_token=form_data['access_token'],
            refresh_token=form_data['refresh_token'],
            expires_at=self._convert_seconds_to_datetime(form_data['expires_in'])
        )

    def delete_user(self):
        self.logger.info("Google ACCOUNT DELETED FOR USER {}".format(self.User))
        GoogleFitUser.objects.filter(user=self.User).delete()

    def save_step_data(self, step_data):
        for activity_step in step_data["point"]:
            StepCountData.objects.get_or_create(
                User=self.User,
                source=self.device_type,
                resource='steps',
                date_of_measurement=self._convert_nanotime_to_timestamp(activity_step['endTimeNanos']),
                value=int(float(activity_step['value']['intVal']))
            )

    def refresh_access_token(self, user_google_fit):


        refresh_token = user_google_fit.refresh_token

        refresh_token_request_header = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        parameters = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': settings.GOOGLE_FIT_CLIENT_ID,
            'client_secret': settings.GOOGLE_FIT_CLIENT_SECRET,
        }

        response = requests.post(
            settings.GOOGLE_FIT_REFRESH_TOKEN_URI,
            params=parameters,
            headers=refresh_token_request_header,
            stream=True
        )

        response = response.json()

        user_google_fit.access_token = response['access_token']
        user_google_fit.expires_in = self._convert_seconds_to_datetime(response['expires_in'])
        user_google_fit.save()

    @staticmethod
    def _convert_nanotime_to_timestamp(nanotime):
        return datetime.datetime.fromtimestamp(int(nanotime) // 1000000000)

    @staticmethod
    def _convert_timestamp_to_nanotime(timestamp):
        nanotime = datetime.datetime.strptime(str(timestamp), "%d.%m.%Y %H:%M:%S,%f").strftime('%s')
        return int(nanotime) * 1000

    def nanoseconds_time_range(self):
        timestamp = StepCountData.objects.filter(
            User=self.User
        ).latest('date_of_measurement').date_of_measurement

        start_time = self._convert_timestamp_to_nanotime(timestamp)
        end_time = self._convert_timestamp_to_nanotime(timezone.now())

        return '{}-{}'.format(start_time, end_time)


def get_connection(User, logger=None):
    device_type = User.objects.get(id=User.id).get_connected_tracker_type()

    if not device_type:
        error_message = 'User ' + User.email + ' does not have active device connection.'
        raise APIException(error_message)

    connections = {
        'fitbit': FitbitConnection,
        'samsung': SamsungConnection,
        'garmin': GarminConnection,
        'google': GoogleConnection,
        'apple': AppleConnection
    }
    connection = connections[device_type](User, device_type, logger)
    return connection


def create_connection(User, device_type, authorization_data, logger=None):
    connections = StepTrackingDevice.objects.filter(
        User=User,
        connection_status=True
    )
    for connection in connections:
        connection.disconnect_device()

    StepTrackingDevice.objects.create(
        User=User,
        connection_name=device_type,
        connection_status=True,
        connection_time=timezone.now(),
        show_steps=True,
        send_weight=True,
        send_weight_goal=True
    )

    connection = get_connection(User, logger)
    connection.connect_device(authorization_data)


class TokenNotRefreshed(Exception):
    pass


class DeviceNotSynced(Exception):
    pass


class ConnectionToFitbitFailed(Exception):
    pass
