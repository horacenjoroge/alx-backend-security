from django.core.management.base import BaseCommand, CommandError
from django.core.cache import cache
from ip_tracking.models import BlockedIP
import ipaddress


class Command(BaseCommand):
    """
    Django management command to block IP addresses.
    
    Usage:
        python manage.py block_ip 192.168.1.1 "Spam bot"
        python manage.py block_ip 10.0.0.5 --unblock
    """
    help = 'Block or unblock an IP address'

    def add_arguments(self, parser):
        """
        Define command-line arguments.
        """
        parser.add_argument(
            'ip_address',
            type=str,
            help='IP address to block or unblock'
        )
        parser.add_argument(
            'reason',
            nargs='?',  # Optional argument
            type=str,
            default='No reason provided',
            help='Reason for blocking this IP'
        )
        parser.add_argument(
            '--unblock',
            action='store_true',
            help='Unblock the IP instead of blocking it'
        )

    def handle(self, *args, **options):
        """
        Main logic for the command.
        """
        ip_address = options['ip_address']
        reason = options['reason']
        unblock = options['unblock']
        
        # Validate the IP address format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            raise CommandError(f'Invalid IP address: {ip_address}')
        
        if unblock:
            # Remove the IP from the blacklist
            deleted_count, _ = BlockedIP.objects.filter(ip_address=ip_address).delete()
            
            if deleted_count > 0:
                # Clear the cache so the unblock takes effect immediately
                cache.delete(f'blocked_ip_{ip_address}')
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully unblocked IP: {ip_address}')
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f'IP {ip_address} was not in the blocklist')
                )
        else:
            # Add the IP to the blacklist
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={'reason': reason}
            )
            
            if created:
                # Clear/set cache so the block takes effect immediately
                cache.set(f'blocked_ip_{ip_address}', True, 300)
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Successfully blocked IP: {ip_address}\n'
                        f'Reason: {reason}'
                    )
                )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f'IP {ip_address} is already blocked\n'
                        f'Existing reason: {blocked_ip.reason}'
                    )
                )