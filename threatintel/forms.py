# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from django import forms

from threatintel.models import Watch


class WatchNoteForm(forms.ModelForm):
    # Only the note is editable; user and vulnerability never come from the form
    class Meta:
        model = Watch
        fields = ["note"]
