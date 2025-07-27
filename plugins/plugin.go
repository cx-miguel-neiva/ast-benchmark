package plugins

type ISourceItem interface {
	GetContent() *string
	GetID() string
	GetSource() string
}

type Item struct {
	Content *string
	ID      string
	Source  string
}

func (i *Item) GetContent() *string {
	return i.Content
}

func (i *Item) GetID() string {
	return i.ID
}

func (i *Item) GetSource() string {
	return i.Source
}
