#[macro_export]
macro_rules! patch {
    ($self:ident, $patcher:ident, $fields:expr) => {
        $patcher
            .description
            .map(|patched| match &$self.description {
                Some(_) => {
                    $self.description = Some(patched);
                }
                None => {
                    $self.description = Some(patched);
                }
            });
        $self
    };
}
